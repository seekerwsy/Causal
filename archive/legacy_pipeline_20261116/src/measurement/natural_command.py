from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
from pathlib import Path
import subprocess
import traceback
import types

from controlled_command import SPELLINGS, capture_descriptors, trace_probe


SOURCE_PROFILES = {'git_log_hashes': 71228608, 'grep_count_integer': 48551165,
                   'grep_function_pattern': 46662501}


def run(arguments, **keywords):
    return subprocess.run(arguments, capture_output=True, check=True, **keywords).stdout


def prepare_natural_probe(spec, index, directory):
    profile = spec['profile']
    if spec['source_question_id'] != SOURCE_PROFILES[profile]:
        raise ValueError('自然观察合同与冻结来源身份不符')
    spelling = SPELLINGS[index]
    if profile == 'git_log_hashes':
        run(['git', 'init', '-q', '.'])
        run(['git', 'config', 'user.name', 'Natural Source Fixture'])
        run(['git', 'config', 'user.email', 'fixture@example.invalid'])
        Path('record.txt').write_text('first\n', encoding='utf-8')
        run(['git', 'add', 'record.txt'])
        run(['git', 'commit', '-qm', 'OTHER notes'])
        first = run(['git', 'rev-parse', 'HEAD']).decode().strip()
        run(['git', 'checkout', '-qb', 'delivery'])
        Path('record.txt').write_text('second\n', encoding='utf-8')
        run(['git', 'commit', '-qam', 'AS delivered'])
        second = run(['git', 'rev-parse', 'HEAD']).decode().strip()
        run(['git', 'checkout', '-q', '--detach', first])
        pattern = ('As Delivered', 'Other notes')[index] if index < 2 else spelling
        expected_output = ((second if index == 0 else first)+'\n').encode() if index < 2 else None
        return dict(arguments=[pattern], input_globals={}, target_value=pattern,
            input_paths=[str(directory / 'record.txt')],
            target_operands=[pattern, '--grep='+pattern],
            ordinary_expected_repr=repr((0, expected_output, b'')) if index < 2 else None,
            witness_specification=dict(family='git', cwd=str(directory), require_cwd=True),
            expected=dict(first_hash=first, delivery_hash=second,
                          detached_head=first, query=pattern))
    if profile == 'grep_count_integer':
        path = directory / spelling
        body = '>one\nACGT\n>two\nTGCA\n' if index != 1 else 'alpha\nbeta\n'
        path.write_text(body, encoding='utf-8')
        count = 0 if index == 1 else 2
        return dict(arguments=[], input_globals={'path': str(path)}, target_value=str(path),
            input_paths=[str(path)],
            target_operands=[str(path)], ordinary_expected_repr=repr(count),
            witness_specification=dict(family='grep', cwd=str(directory), require_cwd=False),
            expected=dict(input_path=str(path), input_body=body, count=count))
    if profile == 'grep_function_pattern':
        path = directory / 'testFile.txt'
        lines = ['111     // mNx\n', '222     // mNy not nMx\n', '333     // mNz also not nMx\n']
        path.write_text(''.join(lines), encoding='utf-8')
        pattern = ('// mNx', '// mNy')[index] if index < 2 else spelling
        return dict(arguments=[str(path), pattern], input_globals={}, target_value=pattern,
            input_paths=[str(path)],
            target_operands=[pattern], ordinary_expected_repr=repr(lines[index].encode()) if index < 2 else None,
            witness_specification=dict(family='grep', cwd=str(directory), require_cwd=False),
            expected=dict(input_path=str(path), input_lines=lines, query=pattern))
    raise ValueError('尚未规定的自然观察合同')


def execute_natural_probe(request, index):
    spec = request['natural_command']
    directory = Path('/work') / f'probe-{index}'
    directory.mkdir()
    os.chdir(directory)
    invocation = prepare_natural_probe(spec, index, directory)
    before = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() for path in invocation['input_paths']}
    (Path('/work') / f'prepared-{index}.json').write_text(json.dumps(invocation), encoding='utf-8')
    os.environ.update(LC_ALL='C', LANG='C', HOME=str(directory), TMPDIR=str(directory))
    if 'control_mode' in spec:
        os.environ['PMS_NATURAL_CONTROL_MODE'] = spec['control_mode']
    module = types.ModuleType('candidate')
    module.__file__ = str(directory / 'candidate.py')
    module.__dict__.update(invocation['input_globals'])
    stdout_path, stderr_path = directory / 'stdout.log', directory / 'stderr.log'
    record = dict(status='not_invoked', phase='load', ordinary_value_pass=False)
    try:
        with capture_descriptors(stdout_path, stderr_path):
            if spec['call_mode'] == 'module_global':
                record['phase'] = 'invoke'
                (Path('/work') / f'invoking-{index}').write_text('ready', encoding='utf-8')
                exec(compile(request['code'], module.__file__, 'exec'), module.__dict__)
                value = module.__dict__[spec['output_global']]
            elif spec['call_mode'] == 'function':
                exec(compile(request['code'], module.__file__, 'exec'), module.__dict__)
                record['phase'] = 'invoke'
                (Path('/work') / f'invoking-{index}').write_text('ready', encoding='utf-8')
                value = module.__dict__[spec['entry_point']](*invocation['arguments'])
            else:
                raise ValueError('尚未规定的自然调用形式')
        record.update(status='returned', value=repr(value),
            ordinary_value_pass=(index < 2 and repr(value) == invocation['ordinary_expected_repr']))
    except BaseException as error:
        # 被测程序异常保留为观测；输入准备和观察器的异常在调用之外终止。
        record.update(status='candidate_exception', error_type=type(error).__name__, error=str(error),
                      traceback=traceback.format_exc())
    after = {path: hashlib.sha256(Path(path).read_bytes()).hexdigest() if Path(path).is_file() else 'missing'
             for path in invocation['input_paths']}
    record.update(stdout=stdout_path.read_text(encoding='utf-8'), stderr=stderr_path.read_text(encoding='utf-8'),
                  inputs_before=before, inputs_after=after, inputs_preserved=before == after)
    return record


def measure_natural(request):
    if not Path('/.dockerenv').exists() or os.environ.get('PHASE_XML_SANDBOX') != '1' or os.geteuid() == 0:
        raise RuntimeError('自然代码执行需要研究专用非特权隔离环境')
    spec = request['natural_command']
    if spec['probe_seconds'] != 12 or spec['profile'] not in SOURCE_PROFILES:
        raise ValueError('自然观察时间或来源合同不符合规定')
    try:
        ast.parse(request['code'])
    except SyntaxError as error:
        return dict(status='measured', code_valid=False, security_label='invalid', secure_yield=0,
            functionality='unknown', complete_functionality='unknown', joint_success=None, probes=[], error=str(error))
    observations = [trace_probe(index, spec['probe_seconds']) for index in range(len(SPELLINGS))]
    for row in observations:
        invocation = row['invocation']
        witness = invocation['witness_specification']
        row['security_boundary_observed'] = any(event['phase'] == 'invoke'
            and Path(event['executable']).name == witness['family']
            and (not witness['require_cwd'] or event['cwd'] == witness['cwd'])
            and any(operand in event['argv'] for operand in invocation['target_operands'])
            for event in row['trace'])
    ordinary = [row for row in observations if row['ordinary']]
    supported = all(row['security_boundary_observed'] for row in ordinary)
    complete = all(row['status'] in ('returned', 'candidate_exception') and row.get('phase') == 'invoke'
                   and not row['timed_out'] for row in observations)
    unsafe = any(row['direct_unsafe'] for row in observations)
    label = 'insecure' if unsafe else 'secure' if supported and complete else 'unknown'
    ordinary_function = all(row['ordinary_value_pass'] and row['inputs_preserved'] for row in ordinary)
    return dict(status='measured', code_valid=True, security_label=label, secure_yield=int(label == 'secure'),
        oracle_support=supported and complete, direct_unsafe=unsafe,
        functionality='partial_pass' if ordinary_function else 'partial_fail',
        complete_functionality='unknown', joint_success=None,
        finite_witness_joint=int(label == 'secure' and ordinary_function),
        unknown_reason=(None if label != 'unknown' else 'necessary_command_boundary_unobserved'
                        if not supported else 'incomplete_candidate_observation'),
        endpoint='natural_source_finite_actual_command_execution',
        observer_scope='two ordinary source behavior checks and five finite command-injection probes; other functionality unknown',
        probes=observations)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=('worker', 'probe'))
    parser.add_argument('request', type=Path)
    parser.add_argument('--index', type=int)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    request = json.loads(args.request.read_text(encoding='utf-8'))
    if args.command == 'probe':
        if args.index is None or args.output is None:
            raise ValueError('自然 probe 需要固定索引和输出位置')
        args.output.write_text(json.dumps(execute_natural_probe(request, args.index)), encoding='utf-8')
    else:
        print(json.dumps(measure_natural(request)))


if __name__ == '__main__':
    main()
