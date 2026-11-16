import argparse
import ast
from concurrent.futures import ThreadPoolExecutor
import json
import subprocess
import sys
import urllib.request
from pathlib import Path, PurePosixPath

from jsonschema import Draft202012Validator
from markdown_it import MarkdownIt

from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_json_new
from prompt_mechanism_study.records import canonical_json


PATCH_OUTPUT_CONTRACT = 'candidate-patch-json-v1'


def candidate_patch_schema(target_path, source_sha256):
    return {
        '$schema': 'https://json-schema.org/draft/2020-12/schema',
        'type': 'object',
        'additionalProperties': False,
        'required': ['contract', 'target_path', 'source_sha256', 'unified_diff'],
        'properties': {
            'contract': {'const': PATCH_OUTPUT_CONTRACT},
            'target_path': {'const': target_path},
            'source_sha256': {'const': source_sha256},
            'unified_diff': {'type': 'string', 'minLength': 1},
        },
    }


def patch_output_instruction(target_path, source_sha256):
    return (
        'OUTPUT CONTRACT\n'
        'Return exactly one JSON object accepted by the supplied JSON Schema. '
        'Set contract, target_path and source_sha256 to their schema constants. '
        'Put exactly one standard unified diff in unified_diff. The diff must apply '
        f'to the supplied source identity and modify only {target_path}. Do not wrap '
        'the JSON in Markdown, add prose, add tests, provide alternatives, or modify '
        'another file. Preserve the complete target module through the applied patch.\n'
        f'DECLARED TARGET: {target_path}\n'
        f'DECLARED SOURCE SHA256: {source_sha256}'
    )


def _unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f'Duplicate JSON object key: {key}')
        result[key] = value
    return result


def parse_candidate_patch(response_text, target_path, source_sha256):
    record = json.loads(response_text, object_pairs_hook=_unique_json_object)
    Draft202012Validator(candidate_patch_schema(target_path, source_sha256)).validate(record)
    return record


def _run_git(arguments, source_root, git_dir):
    completed = subprocess.run(
        [
            'git', '-c', 'core.autocrlf=false', '-C', str(source_root),
            f'--git-dir={git_dir / ".git"}',
            f'--work-tree={source_root}', *arguments,
        ],
        cwd=source_root, capture_output=True, text=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"git {' '.join(arguments)} failed with {completed.returncode}: {completed.stderr}")
    return completed


def _validate_target_path(target_path):
    candidate = PurePosixPath(target_path)
    if candidate.is_absolute() or '..' in candidate.parts or candidate.as_posix() != target_path:
        raise ValueError(f'Invalid declared target path: {target_path}')


def _validate_candidate_syntax(source_root, target, syntax_check):
    if syntax_check['kind'] == 'python_ast':
        ast.parse(target.read_text(encoding='utf-8'))
        return {'kind': 'python_ast', 'status': 'passed'}
    if syntax_check['kind'] != 'command':
        raise ValueError(f"Unsupported syntax check kind: {syntax_check['kind']}")
    replacements = {'{source_root}': str(source_root), '{target}': str(target)}
    command = [replacements.get(part, part) for part in syntax_check['command']]
    completed = subprocess.run(
        command, cwd=source_root, capture_output=True, text=True, check=False,
        timeout=syntax_check['timeout_seconds'])
    if completed.returncode != 0:
        raise RuntimeError(
            f"Candidate syntax command failed with {completed.returncode}: {completed.stderr}")
    return {
        'kind': 'command',
        'status': 'passed',
        'command': command,
        'stdout': completed.stdout,
        'stderr': completed.stderr,
    }


def apply_candidate_patch(
        response_text, source_root, target_path, source_sha256, artifact_dir, syntax_check):
    source_root = source_root.resolve()
    artifact_dir = artifact_dir.resolve()
    _validate_target_path(target_path)
    artifact_dir.mkdir(parents=True, exist_ok=False)
    raw_response = artifact_dir / 'raw-response.txt'
    raw_response.write_text(response_text, encoding='utf-8', newline='\n')
    record = parse_candidate_patch(response_text, target_path, source_sha256)
    target = source_root / PurePosixPath(target_path)
    if not target.is_file():
        raise FileNotFoundError(f'Declared target is absent: {target}')
    if file_sha256(target) != source_sha256:
        raise ValueError('Declared source SHA256 does not match the target file')
    patch_path = artifact_dir / 'candidate.diff'
    patch_path.write_text(record['unified_diff'], encoding='utf-8', newline='\n')
    git_dir = artifact_dir / 'git-worktree'
    initialized = subprocess.run(
        ['git', 'init', '--quiet', str(git_dir)], capture_output=True, text=True, check=False)
    if initialized.returncode != 0:
        raise RuntimeError(f'Unable to initialize isolated Git metadata: {initialized.stderr}')
    _run_git(['apply', '--check', str(patch_path)], source_root, git_dir)
    numstat = _run_git(['apply', '--numstat', str(patch_path)], source_root, git_dir)
    modified_paths = []
    for line in numstat.stdout.splitlines():
        fields = line.split('\t')
        if len(fields) != 3:
            raise ValueError(f'Unexpected git apply --numstat row: {line}')
        modified_paths.append(fields[2])
    if modified_paths != [target_path]:
        raise ValueError(f'Modified path set does not equal the declared target: {modified_paths}')
    original_sha256 = file_sha256(target)
    _run_git(['apply', str(patch_path)], source_root, git_dir)
    if not target.is_file():
        raise ValueError('Candidate removed the declared target file')
    candidate_sha256 = file_sha256(target)
    if candidate_sha256 == original_sha256:
        raise ValueError('Candidate produced no target-file change')
    syntax = _validate_candidate_syntax(source_root, target, syntax_check)
    return {
        'status': 'CANDIDATE_APPLIED_AND_SYNTAX_CHECKED',
        'contract': PATCH_OUTPUT_CONTRACT,
        'target_path': target_path,
        'source_sha256': source_sha256,
        'candidate_sha256': candidate_sha256,
        'modified_paths': modified_paths,
        'raw_response_sha256': file_sha256(raw_response),
        'patch_sha256': file_sha256(patch_path),
        'syntax_check': syntax,
    }


def _load_validated(path, schema_path):
    record = read_json(path)
    Draft202012Validator(read_json(schema_path)).validate(record)
    return record


def verify_semantic_generation_entry(path):
    entry = read_json(path)
    base = path.resolve().parent
    schema_paths = entry['schemas']
    Draft202012Validator(read_json(base / schema_paths['entry'])).validate(entry)
    rules_path = base / entry['binding_attribute_rules']['path']
    if file_sha256(rules_path) != entry['binding_attribute_rules']['sha256']:
        raise ValueError('Binding and attribute rule identity mismatch')
    rules = read_json(rules_path)
    if rules['status'] != 'FROZEN_BEFORE_INDEPENDENT_SEMANTIC_REVIEW':
        raise ValueError('Binding and attribute rules were not prospectively frozen')
    expected_ids = set(entry['required_representation_ids'])
    fact_ids = set()
    for reference in entry['fact_inventories']:
        record_path = base / reference['path']
        if file_sha256(record_path) != reference['sha256']:
            raise ValueError(f"Fact inventory identity mismatch: {reference['representation_id']}")
        record = _load_validated(record_path, base / schema_paths['facts'])
        if record['representation_id'] != reference['representation_id']:
            raise ValueError('Fact inventory representation identity mismatch')
        fact_ids.add(record['representation_id'])
    review_ids = set()
    for reference in entry['semantic_reviews']:
        record_path = base / reference['path']
        if file_sha256(record_path) != reference['sha256']:
            raise ValueError(f"Semantic review identity mismatch: {reference['representation_id']}")
        record = _load_validated(record_path, base / schema_paths['review'])
        if record['representation_id'] != reference['representation_id']:
            raise ValueError('Semantic review representation identity mismatch')
        if record['critical_errors'] or record['unresolved_critical_unknowns']:
            raise ValueError(f"Critical semantic blocker: {record['representation_id']}")
        if record['entry_decision'] != 'PASS':
            raise ValueError(f"Semantic review did not pass: {record['representation_id']}")
        review_ids.add(record['representation_id'])
    if fact_ids != expected_ids or review_ids != expected_ids:
        raise ValueError('Fact inventories and semantic reviews must cover every representation')
    budget_ids = {row['representation_id'] for row in entry['token_budgets']}
    if budget_ids != expected_ids:
        raise ValueError('Token budgets must cover every representation')
    for row in entry['token_budgets']:
        if row['input_tokens'] + row['max_output_tokens'] > row['service_context_tokens']:
            raise ValueError(f"Token budget exceeded: {row['representation_id']}")
    return entry


def _replace_once(text, old, new, label):
    if text.count(old) != 1:
        raise ValueError(f'Expected exactly one frozen replacement for {label}')
    return text.replace(old, new, 1)


def prepare_patch_representations(plan_path, output):
    plan = read_json(plan_path)
    project = plan_path.resolve().parents[3]
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for assigned in plan['requests']:
        source_path = project / assigned['representation_path']
        if file_sha256(source_path) != assigned['representation_sha256']:
            raise ValueError(f"Representation identity mismatch: {assigned['request_id']}")
        text = source_path.read_text(encoding='utf-8')
        for index, replacement in enumerate(assigned['representation_replacements']):
            text = _replace_once(
                text, replacement['old'], replacement['new'],
                f"{assigned['request_id']} representation replacement {index}")
        destination = output / f"{assigned['request_id']}.txt"
        destination.write_text(text, encoding='utf-8', newline='\n')
        rows.append({
            'request_id': assigned['request_id'],
            'representation_id': assigned['representation_id'],
            'source_sha256': assigned['representation_sha256'],
            'prepared_sha256': file_sha256(destination),
            'path': destination.name,
        })
    write_json_new(output / 'manifest.json', {
        'status': 'PATCH_REPRESENTATIONS_PREPARED_BEFORE_SUBJECT_GENERATION',
        'study_id': plan['study_id'],
        'rows': rows,
    })


def freeze_patch_requests(plan_path, prepared_representations, output):
    plan = read_json(plan_path)
    project = plan_path.resolve().parents[3]
    manifest = read_json(prepared_representations / 'manifest.json')
    manifest_rows = {row['request_id']: row for row in manifest['rows']}
    output.mkdir(parents=True, exist_ok=False)
    rows = []
    for assigned in plan['requests']:
        legacy_prompt_path = project / assigned['legacy_prompt_path']
        if file_sha256(legacy_prompt_path) != assigned['legacy_prompt_sha256']:
            raise ValueError(f"Legacy prompt identity mismatch: {assigned['request_id']}")
        legacy_prompt = read_json(legacy_prompt_path)
        if [row['role'] for row in legacy_prompt['messages']] != ['system', 'user']:
            raise ValueError('Expected one system and one user message')
        original_representation = (
            project / assigned['representation_path']).read_text(encoding='utf-8').removesuffix('\n')
        prepared_path = prepared_representations / manifest_rows[assigned['request_id']]['path']
        if file_sha256(prepared_path) != manifest_rows[assigned['request_id']]['prepared_sha256']:
            raise ValueError('Prepared representation identity mismatch')
        prepared_representation = prepared_path.read_text(encoding='utf-8').removesuffix('\n')
        user = legacy_prompt['messages'][1]['content']
        user = _replace_once(
            user, assigned['legacy_task_instruction'], assigned['semantic_task_instruction'],
            f"{assigned['request_id']} task instruction")
        user = _replace_once(
            user, original_representation, prepared_representation,
            f"{assigned['request_id']} representation")
        user = _replace_once(
            user, plan['legacy_output_contract'],
            patch_output_instruction(assigned['target_path'], assigned['source_sha256']),
            f"{assigned['request_id']} output contract")
        for forbidden in plan['forbidden_output_instructions']:
            if forbidden in user:
                raise ValueError(
                    f"Conflicting output instruction remains in {assigned['request_id']}: {forbidden}")
        schema = candidate_patch_schema(assigned['target_path'], assigned['source_sha256'])
        request = {
            'model': plan['model'],
            'messages': [
                {
                    'role': 'system',
                    'content': (
                        'Return exactly one JSON object matching the supplied strict JSON Schema. '
                        'Do not execute code.'),
                },
                {'role': 'user', 'content': user},
            ],
            'max_tokens': plan['generation']['max_tokens'],
            'temperature': plan['generation']['temperature'],
            'top_p': plan['generation']['top_p'],
            'seed': assigned['seed'],
            'n': 1,
            'response_format': {
                'type': 'json_schema',
                'json_schema': {'name': 'candidate_patch', 'strict': True, 'schema': schema},
            },
        }
        destination = output / f"{assigned['request_id']}.json"
        write_json_new(destination, request)
        rows.append({
            'request_id': assigned['request_id'],
            'representation_id': assigned['representation_id'],
            'request_sha256': file_sha256(destination),
            'target_path': assigned['target_path'],
            'source_sha256': assigned['source_sha256'],
            'seed': assigned['seed'],
        })
    write_json_new(output / 'manifest.json', {
        'status': 'SIX_PATCH_REQUESTS_FROZEN_BEFORE_SUBJECT_GENERATION',
        'study_id': plan['study_id'],
        'request_limit': len(rows),
        'retry': False,
        'rows': rows,
    })


def request_frozen_patches(plan_path, entry_path, requests_root, output):
    plan = read_json(plan_path)
    entry = verify_semantic_generation_entry(entry_path)
    if entry['study_id'] != plan['study_id']:
        raise ValueError('Semantic entry and request plan identities differ')
    manifest = read_json(requests_root / 'manifest.json')
    if manifest['request_limit'] != len(plan['requests']):
        raise ValueError('Frozen request denominator mismatch')
    output.mkdir(parents=True, exist_ok=False)
    completed = []
    for assigned in plan['requests']:
        row, = [item for item in manifest['rows'] if item['request_id'] == assigned['request_id']]
        request_path = requests_root / f"{assigned['request_id']}.json"
        if file_sha256(request_path) != row['request_sha256']:
            raise ValueError(f"Frozen request identity mismatch: {assigned['request_id']}")
        request_data = request_path.read_bytes()
        request = urllib.request.Request(
            plan['base_url'] + '/chat/completions', data=request_data,
            headers={'Content-Type': 'application/json'})
        assignment_output = output / assigned['request_id']
        assignment_output.mkdir()
        (assignment_output / 'request.json').write_bytes(request_data)
        with urllib.request.urlopen(request, timeout=plan['timeout_seconds']) as response:
            if response.status != 200:
                raise RuntimeError(f"HTTP status {response.status}: {assigned['request_id']}")
            raw_response = response.read()
        (assignment_output / 'raw-response.json').write_bytes(raw_response)
        response_record = json.loads(raw_response.decode('utf-8'))
        choices = response_record['choices']
        if len(choices) != 1 or not isinstance(choices[0]['message']['content'], str):
            raise ValueError(f"Invalid response envelope: {assigned['request_id']}")
        content = choices[0]['message']['content']
        (assignment_output / 'candidate-response.txt').write_text(
            content, encoding='utf-8', newline='\n')
        completed.append({
            'request_id': assigned['request_id'],
            'request_sha256': file_sha256(assignment_output / 'request.json'),
            'raw_response_sha256': file_sha256(assignment_output / 'raw-response.json'),
            'candidate_response_sha256': file_sha256(
                assignment_output / 'candidate-response.txt'),
            'finish_reason': choices[0].get('finish_reason'),
            'usage': response_record.get('usage'),
            'retry': False,
        })
    write_json_new(output / 'generation-complete.json', {
        'status': 'SIX_FIXED_DEVELOPMENT_REQUESTS_HAVE_RESPONSES',
        'study_id': plan['study_id'],
        'assigned': len(plan['requests']),
        'completed': completed,
        'retry': False,
    })


def verify_generation_plan(path):
    plan = read_json(path)
    project = path.resolve().parents[3]
    for name, expected in plan['hashes'].items():
        assert file_sha256(project/name) == expected, name
    assert len(plan['requests']) == plan['request_limit']
    assert len({row['request_id'] for row in plan['requests']}) == plan['request_limit']
    return plan


def assigned_prompt(plan, assigned):
    if 'task_unit_id' in assigned:
        return plan['prompts'][assigned['task_unit_id']][assigned['arm']]
    return plan['prompts'][assigned['arm']]


def generation_payload(plan,assigned):
    payload = dict(model=plan['model'],messages=[dict(role='system',content=plan['system']),
        dict(role='user',content=assigned_prompt(plan,assigned))],seed=assigned['seed'],**plan['generation'])
    if plan.get('output_contract') == PATCH_OUTPUT_CONTRACT:
        schema = candidate_patch_schema(assigned['target_path'], assigned['source_sha256'])
        payload['response_format'] = {
            'type': 'json_schema',
            'json_schema': {'name': 'candidate_patch', 'strict': True, 'schema': schema},
        }
    return payload


def request_assigned_code(plan_path,output,request_id):
    plan = verify_generation_plan(plan_path)
    assigned, = [row for row in plan['requests'] if row['request_id'] == request_id]
    payload = generation_payload(plan,assigned)
    write_json_new(output/f'{request_id}-request.json',payload)
    request = urllib.request.Request(plan['base_url']+'/chat/completions',data=canonical_json(payload).encode('utf-8'),
        headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(request,timeout=plan['timeout_seconds']) as response:
        assert response.status == 200
        raw = json.loads(response.read().decode('utf-8'))
    assert len(raw['choices']) == 1 and isinstance(raw['choices'][0]['message']['content'],str)
    write_json_new(output/f'{request_id}-response.json',raw)


def generate_assigned_code(plan_path,output):
    plan_path = plan_path.resolve()
    plan = verify_generation_plan(plan_path)
    output.mkdir(parents=True,exist_ok=False)
    with urllib.request.urlopen(plan['base_url']+'/models',timeout=15) as response:
        models = json.loads(response.read().decode('utf-8'))
    assert plan['model'] in {row['id'] for row in models['data']}
    write_json_new(output/'allocation.json',dict(plan_sha256=file_sha256(plan_path),models=models,requests=plan['requests']))

    def execute(assigned):
        key = assigned['request_id']
        completed = subprocess.run([sys.executable,'-m','prompt_mechanism_study.experiment.code_generation','request',
            str(plan_path),str(output),'--request-id',key],capture_output=True,text=True,check=False,
            timeout=plan['timeout_seconds']+30)
        (output/f'{key}.stdout.txt').write_text(completed.stdout,encoding='utf-8',newline='\n')
        (output/f'{key}.stderr.txt').write_text(completed.stderr,encoding='utf-8',newline='\n')
        terminal = dict(**assigned,status='completed' if completed.returncode == 0 else 'request_failed',exit_code=completed.returncode)
        write_json_new(output/f'{key}-terminal.json',terminal)
        return terminal

    with ThreadPoolExecutor(max_workers=plan['workers']) as executor:
        terminals = list(executor.map(execute,plan['requests']))
    write_json_new(output/'generation-completed.json',dict(allocated=plan['request_limit'],terminals=terminals))
    print(dict(status='GENERATION_REQUESTS_FINISHED',allocated=plan['request_limit'],
        completed=sum(row['status'] == 'completed' for row in terminals)),flush=True)


def extract_assigned_code(plan_path,output):
    plan = verify_generation_plan(plan_path)
    parser = MarkdownIt('commonmark')
    rows = []
    for assigned in plan['requests']:
        key = assigned['request_id']
        terminal = read_json(output/f'{key}-terminal.json')
        assert all(terminal[name] == value for name,value in assigned.items())
        if terminal['status'] != 'completed':
            rows.append(dict(**assigned,status='request_failed',usable=False))
            continue
        raw = read_json(output/f'{key}-response.json')
        content = raw['choices'][0]['message']['content']
        blocks = [token for token in parser.parse(content) if token.type in ('fence','code_block')]
        if len(blocks) > 1:
            rows.append(dict(**assigned,status='ambiguous_code_blocks',usable=False))
            continue
        language = assigned.get('language','python')
        if blocks and blocks[0].type == 'fence' and blocks[0].info.strip().lower() not in ('',language,'py' if language == 'python' else language):
            rows.append(dict(**assigned,status='mismatched_code_block_language',usable=False))
            continue
        code = blocks[0].content if blocks else content
        suffix = assigned.get('target_suffix','.py')
        assert suffix.startswith('.') and suffix.replace('.','').isalnum()
        path = output/f'{key}{suffix}'
        with path.open('x',encoding='utf-8',newline='\n') as stream:
            stream.write(code)
        usable, reason, syntax_checked = bool(code.strip()), None, suffix == '.py'
        if syntax_checked:
            try:
                ast.parse(code)
            except SyntaxError as error:
                usable, reason = False, str(error)
        elif code.lstrip().startswith(('diff --git ','--- a/','*** Begin Patch')):
            usable, reason = False, 'patch output is not a complete target file'
        status = ('parseable' if usable else 'invalid_syntax') if syntax_checked else ('extracted' if usable else 'invalid_source')
        rows.append(dict(**assigned,status=status,usable=usable,reason=reason,
            syntax_checked=syntax_checked,target_suffix=suffix,
            source_sha256=file_sha256(path),finish_reason=raw['choices'][0]['finish_reason'],usage=raw.get('usage'),
            response_sha256=file_sha256(output/f'{key}-response.json')))
    write_json_new(output/'extraction.json',dict(assigned=plan['request_limit'],rows=rows,plan_sha256=file_sha256(plan_path)))
    print(dict(status='CODE_EXTRACTION_FINISHED',assigned=plan['request_limit'],parseable=sum(row['usable'] for row in rows)),flush=True)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('stage',choices=(
        'generate', 'request', 'extract', 'prepare-patch-representations',
        'freeze-patch-requests', 'request-frozen-patches'))
    parser.add_argument('plan',type=Path)
    parser.add_argument('output',type=Path)
    parser.add_argument('--request-id')
    parser.add_argument('--prepared-representations',type=Path)
    parser.add_argument('--entry',type=Path)
    parser.add_argument('--requests-root',type=Path)
    args = parser.parse_args()
    if args.stage == 'request':
        assert args.request_id is not None
        request_assigned_code(args.plan,args.output,args.request_id)
    elif args.stage == 'prepare-patch-representations':
        prepare_patch_representations(args.plan,args.output)
    elif args.stage == 'freeze-patch-requests':
        if args.prepared_representations is None:
            raise ValueError('--prepared-representations is required')
        freeze_patch_requests(args.plan,args.prepared_representations,args.output)
    elif args.stage == 'request-frozen-patches':
        if args.entry is None or args.requests_root is None:
            raise ValueError('--entry and --requests-root are required')
        request_frozen_patches(args.plan,args.entry,args.requests_root,args.output)
    else:
        dict(generate=generate_assigned_code,extract=extract_assigned_code)[args.stage](args.plan,args.output)
