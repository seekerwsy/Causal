"""Construct offline annotation responses from explicit source-authored graph facts."""
from copy import deepcopy


def authored_two_output_candidate():
    """Small source-authored ADD fixture; no study generator or reference program."""
    from prompt_mechanism_study.tsg.candidate_construction import knowledge_add_candidate

    first = 'Read source_path and write first_path with the records unchanged.'
    second = 'From the same input, write second_path with the reversed records.'
    prompt = '\n'.join([
        'Implement solve(source_path, first_path, second_path). All arguments are file paths.',
        first, second, 'Return [first_path, second_path].',
        'The records are confidential. Both outputs may be created or overwritten.',
        'Preserve input content and permissions, directory modes and caller umask.',
    ])

    def fact(key, kind, definition, quote):
        return dict(record_id=key, fact=dict(concept=dict(concept_id=key,
            node_type=kind, definition=definition), evidence_text=quote, layer='runtime'))

    objects = [fact(key, 'data_object', definition, quote) for key, definition, quote in [
        ('input_file', 'The read-only input file at source_path.', 'source_path'),
        ('first_file', 'The ordinary output file at first_path.', 'first_path'),
        ('second_file', 'The ordinary output file at second_path.', 'second_path'),
    ]]
    operations, requirements = [], []
    for suffix, clause in [('first', first), ('second', second)]:
        target = suffix + '_file'
        operation = fact('write_' + suffix, 'task_operation', clause, clause)
        operation.update(inputs=[dict(subject='input_file', role='resource', evidence_text=clause)],
            results=[dict(subject=target, evidence_text=clause)], execution_conditions=[],
            scope_conditions=[], precedes=[])
        operations.append(operation)
        requirement = fact('content_' + suffix, 'task_requirement', clause, clause)
        requirement.update(modality='obligation', structure=dict(kind='opaque', members=[]),
            scope_kind='targets', subjects=[target], operations=[], conditions=[],
            target_class=None, relations=[])
        requirements.append(requirement)
    records = dict(objects=objects, operations=operations, requirements=requirements,
                   unit_impacts={}, unresolved_notes=[])
    knowledge = dict(id='critical-file-access', version='test-fixture',
        url='https://cwe.mitre.org/data/definitions/732.html',
        principle='Restrict access to confidential files to the intended user.')
    binding = dict(targets=['first_file', 'second_file'], operations=['write_first', 'write_second'],
        conditions=[], time='normal return', scope='complete two-output set; new and overwritten',
        requirement='Final ordinary output modes have no group/other permission bits.',
        endpoint='final_file_access_and_permission_bits')
    assessment = dict(author='source-authored test fixture', source_state='UNEXPRESSED',
        compatibility='compatible', relevance='supported', complete_binding=True,
        evidence=[first, second, 'The records are confidential.'],
        non_target_invariants=['Both output contents and return paths; input, directories and umask.'],
        rationale='One final permission property covers both outputs without changing their contents.')
    proposal = knowledge_add_candidate(source_prompt=prompt, source_records=records,
                                       knowledge=knowledge, binding=binding, assessment=assessment)
    return dict(prompt=prompt, source_records=records, proposal=proposal), knowledge


def _authored_roles(canonical):
    if "operation_roles" in canonical:
        return deepcopy(canonical["operation_roles"])
    roles = {}
    for edge in canonical["edges"]:
        kind = edge["edge_type"]
        if kind not in {"used_by", "produces"}:
            continue
        source, target = edge["source_node_local_id"], edge["target_node_local_id"]
        operation, subject, role = ((target, source, "input_unspecified") if kind == "used_by"
                                    else (source, target, "result"))
        roles[(operation, subject, role)] = dict(operation=operation, subject=subject, role=role,
            evidence_text=edge["evidence_text"], occurrence=edge.get("occurrence", 1))
    return list(roles.values())


def authored_source_inventory(prompt, canonical):
    """Explicit fixture metadata derived from authored facts/edges, not the extractor."""
    return dict(source_units={"u1": dict(evidence_text=prompt, occurrence=1)},
        coverage={"u1": dict(facts=[n["local_id"] for n in canonical["nodes"]],
            status="represented", reason="Complete source-authored synthetic fixture.")},
        layers={n["local_id"]: n.get("layer", "runtime") for n in canonical["nodes"]},
        operation_roles=_authored_roles(canonical))


def scope_answer(scope, *, expression="not_expressed", applicability="applicable", requirements=()):
    """Explicit source-authored applicability and expression judgments for tests."""
    answer = dict(expression=expression, requirements=list(requirements))
    if "subject_property" not in scope:
        answer.update(applicability=applicability,
                      applicability_rationale="The authored fixture resolves the operation and subject roles.")
    return answer


def quoted_inventory(request, value):
    """Convert authored token fixtures to the model's source-unit quote format."""
    source, tokens, offset = request['source_prompt'], {}, 0
    for key, word in sorted(request['source_tokens'].items(), key=lambda item: int(item[0])):
        left = source.index(word, offset)
        offset = left + len(word)
        tokens[int(key)] = (left, offset)
    units = {}
    for key, unit in request['source_units'].items():
        left = -1
        for _ in range(unit['occurrence']):
            left = source.index(unit['evidence_text'], left + 1)
        units[key] = (left, left + len(unit['evidence_text']))

    def convert(item):
        if isinstance(item, list):
            return [convert(v) for v in item]
        if not isinstance(item, dict):
            return item
        result = {k: convert(v) for k, v in item.items()}
        if 'evidence_start_token' in result and 'evidence_end_token' in result:
            if request['known_concepts'].get(result.get('concept_id'), {}).get('node_type') == 'data_object':
                result['entity_key'] = 'entity_' + result['concept_id'] + '_' + str(result['evidence_start_token'])
            left = tokens[result.pop('evidence_start_token')][0]
            right = tokens[result.pop('evidence_end_token')][1]
            unit = next(k for k, (a, b) in units.items() if a <= left < right <= b)
            result.update(evidence_source_unit=unit, evidence_text=source[left:right])
        return result
    return convert(value)


def indexed_annotation(request, canonical):
    """Test data conversion only; this is not an extractor or semantic reference."""
    if request['request_kind'] in {'source_only_atomic_records', 'source_only_record_review'}:
        return record_annotation(request, canonical)
    source = request["source_prompt"]
    starts, ends, offset = {}, {}, 0
    for key, text in sorted(request["source_tokens"].items(), key=lambda item: int(item[0])):
        position = source.index(text, offset)
        starts[position] = int(key)
        offset = position + len(text)
        ends[offset] = int(key)

    def span(row):
        quote, occurrence = row["evidence_text"], row.get("occurrence", 1)
        position = -1
        for _ in range(occurrence):
            position = source.index(quote, position + 1)
        return position, position + len(quote)

    def evidence(row):
        position, end = span(row)
        return dict(evidence_start_token=starts[position], evidence_end_token=ends[end])

    template = request.get("fixed_template", {})
    template_ids = {n["concept_id"]: n["local_id"] for n in template.get("nodes", [])}
    if request["request_kind"] == "source_only_fact_inventory":
        coverage, nodes = {}, []
        concepts = {c["concept_id"]: c for c in canonical["concepts"]}
        for n in canonical["nodes"]:
            if n["concept_id"] in template_ids:
                continue
            units = [key for key, unit in request["source_units"].items()
                     if span(unit)[0] < span(n)[1] and span(n)[0] < span(unit)[1]]
            meaning = dict(concept_id=n["concept_id"]) if request["concept_policy"] == "FROZEN" else dict(concept=deepcopy(concepts[n["concept_id"]]))
            nodes.append(dict(**meaning, source_units=units, layer=n.get("layer", "runtime"), **evidence(n)))
        for key, unit in request["source_units"].items():
            facts = [n for n in nodes if key in n["source_units"]]
            # Mechanical fixture conversion only, never a source-semantic judgment.
            coverage[key] = dict(status="represented" if facts else "no_task_fact",
                                 reason="Source-authored synthetic fixture segment disposition.")
        return dict(nodes=nodes, coverage=coverage,
                    unresolved_notes=deepcopy(canonical["unresolved_notes"]))
    raise AssertionError("unsupported fixture annotation format")


def record_annotation(request, canonical):
    """Map independently authored fixture edges to complete source records."""
    from prompt_mechanism_study.tsg.source_codec import _source_tokens
    if request['request_kind'] == 'source_only_record_review':
        return dict(records={r['record_id']: dict(status='supported', reason='Source-authored fixture.', rejected_claims=[])
            for group in ('objects', 'operations', 'requirements') for r in request['records'][group]},
            source_units={key: dict(complete=True, reason='Source-authored fixture coverage.')
                          for key in request['source_units']})
    base = {**request, 'request_kind': 'source_only_fact_inventory',
            'source_tokens': {str(i): t.group() for i,t in enumerate(_source_tokens(request['source_prompt']),1)}}
    indexed = indexed_annotation(base, canonical)
    template = {n['concept_id'] for n in request['fixed_template']['nodes']}
    authored = [n for n in canonical['nodes'] if n['concept_id'] not in template]
    meanings = {c['concept_id']: c for c in canonical.get('concepts', [])}
    meanings.update(request['known_concepts'])
    def quote(row):
        # Cross-sentence authored spans use all their source premises. The anchor
        # itself must fit in one unit; the complete premises stay in source_units.
        value = row['evidence_text']
        source = request['source_prompt']
        position = -1
        for _ in range(row.get('occurrence', 1)):
            position = source.index(value, position + 1)
        def contains(unit):
            start = -1
            for _ in range(unit['occurrence']):
                start = source.index(unit['evidence_text'], start + 1)
            return start <= position and position + len(value) <= start + len(unit['evidence_text'])
        unit = next((k for k,u in request['source_units'].items() if contains(u)), None)
        if unit is None:
            unit = next(k for k,u in request['source_units'].items() if u['evidence_text'] in value)
            value = request['source_units'][unit]['evidence_text']
        text = request['source_units'][unit]['evidence_text']
        if text.count(value) > 1:
            value = text[:text.index(value)+len(value)]
        return dict(evidence_source_unit=unit, evidence_text=value)
    facts = {}
    for original, item in zip(authored, indexed['nodes']):
        fact = {k:v for k,v in item.items() if not k.startswith('evidence_')}
        fact.update(quote(original))
        facts[original['local_id']] = fact
    types = {n['local_id']: meanings[n['concept_id']]['node_type'] for n in authored}
    result = dict(objects=[], operations=[], requirements=[], coverage=indexed['coverage'], unresolved_notes=indexed['unresolved_notes'])
    result['unit_impacts'] = {key: dict(effect='global', operations=[], reason='Authored complete fixture; no local exemption.',
        evidence_source_unit=key, evidence_text=unit['evidence_text']) for key,unit in request['source_units'].items()}
    roles = _authored_roles(canonical)
    for n in authored:
        key, kind = n['local_id'], types[n['local_id']]
        if kind == 'condition': continue
        row = dict(record_id=key, fact=facts[key])
        guards = [facts[e['source_node_local_id']] for e in canonical['edges']
                  if e['edge_type']=='conditions' and e['target_node_local_id']==key]
        if kind == 'data_object': result['objects'].append(row)
        elif kind == 'task_operation':
            row.update(inputs=[dict(subject=r['subject'], role=r['role'], **quote(r)) for r in roles if r['operation']==key and r['role']!='result'],
                results=[dict(subject=r['subject'], **quote(r)) for r in roles if r['operation']==key and r['role']=='result'],
                execution_conditions=guards, scope_conditions=[facts[e['source_node_local_id']] for e in canonical['edges']
                    if e['edge_type']=='context_for' and e['target_node_local_id']==key], precedes=[dict(operation=e['target_node_local_id'], **quote(e))
                    for e in canonical['edges'] if e['edge_type']=='precedes' and e['source_node_local_id']==key])
            result['operations'].append(row)
        else:
            targets = [e['target_node_local_id'] for e in canonical['edges'] if e['edge_type']=='constrains' and e['source_node_local_id']==key]
            row.update(modality='obligation', structure=deepcopy(canonical.get('requirement_structures', {}).get(key, dict(kind='atom', members=[]))),
                scope_kind='implementation' if facts[key].get('layer')=='generation' else 'targets',
                operations=[t for t in targets if types.get(t)=='task_operation'], subjects=[t for t in targets if types.get(t)=='data_object'], conditions=guards,
                target_class=None, relations=deepcopy(canonical.get('requirement_relations', {}).get(key, [])))
            if row['structure']['kind'] in {'and','or','not'}:
                row.update(scope_kind='composite',operations=[],subjects=[])
            result['requirements'].append(row)
    return result
