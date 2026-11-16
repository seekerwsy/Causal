from __future__ import annotations

from pathlib import Path

import networkx as nx

from prompt_mechanism_study.artifact_io import file_sha256, read_json_exact, write_json_new
from prompt_mechanism_study.records import content_hash


POLICIES = ('local', 'example', 'reference')


def directional_context_versions(source,annotation):
    from prompt_mechanism_study.records import content_hash
    from prompt_mechanism_study.tsg.prompt_contract import open_concept_catalog
    from prompt_mechanism_study.tsg.prompt_tsg import build_prompt_tsg, prompt_tsg_record, requirement_binding
    prompt = source['prompt']
    if content_hash(prompt)!=source['prompt_hash']:
        raise ValueError('准备来源提示身份不同')
    original = prompt.split('\n\n')
    matching = [index for index,text in enumerate(original) if annotation['primary_operation'] in text]
    if len(matching)!=1 or prompt.count(annotation['primary_operation'])!=1:
        raise ValueError('主操作必须具有唯一逐字来源')
    index = matching[0]
    primary_role = 'The primary collection is identified by primary.'
    comparison_role = 'The comparison collection is identified by comparison.'
    for quote in (primary_role,comparison_role,annotation['comparison_operation']):
        if prompt.count(quote)!=1:
            raise ValueError('操作或参数绑定引用必须唯一')
    catalog = open_concept_catalog()
    meanings = dict(primary_path=('data_object',primary_role),comparison_path=('data_object',comparison_role),
        primary_operation=('task_operation',annotation['primary_operation']),
        comparison_operation=('task_operation',annotation['comparison_operation']),
        no_shell=('safety_requirement',annotation['requirement']))
    meanings.update({f'unit_{i}':('constraint',text) for i,text in enumerate(original)})
    for name,(kind,meaning) in meanings.items():
        catalog['semantics'][name] = kind
        catalog['semantic_guidance'][name] = meaning
    versions = []
    for layout,reference in ((0,0),(0,1),(1,0),(1,1)):
        paragraphs = list(enumerate(original))
        if layout:
            block = paragraphs.pop(index)
            paragraphs.insert(len(paragraphs)-1,block)
        primary_quote = annotation['reference_operation'] if reference else annotation['primary_operation']
        paragraphs = [(i,text.replace(annotation['primary_operation'],primary_quote)) for i,text in paragraphs]
        base = '\n\n'.join(text for _,text in paragraphs)
        normalized = base.replace(annotation['reference_operation'],annotation['primary_operation'])
        if sorted(normalized.split('\n\n'))!=sorted(original):
            raise ValueError('上下文编辑没有保留完整非目标来源段落')
        pair = []
        for arm in (0,1):
            text = base+('\n\nAdditional security requirement: '+annotation['requirement'] if arm else '')
            citations = dict(primary_path=primary_role,comparison_path=comparison_role,
                primary_operation=primary_quote,comparison_operation=annotation['comparison_operation'])
            citations.update({f'unit_{i}':paragraph for i,paragraph in paragraphs})
            if arm:
                citations['no_shell'] = annotation['requirement']
            facts = [dict(local_id=name,node_type=meanings[name][0],semantic_id=name,
                evidence_text=quote,occurrence=1,attributes={}) for name,quote in citations.items()]
            relations = [dict(source='primary_path',edge_type='used_by',target='primary_operation'),
                         dict(source='comparison_path',edge_type='used_by',target='comparison_operation')]
            if arm:
                relations.append(dict(source='no_shell',edge_type='constrains',target='primary_operation'))
            structures = {f'unit_{i}':dict(kind='opaque',members=[]) for i in range(len(original))}
            if arm:
                structures['no_shell'] = dict(kind='atom',members=[])
            graph = build_prompt_tsg(task_id=source['task_unit_id'],prompt=text,
                extractor_id='Codex-authored-directional-preparation',catalog=catalog,
                facts=facts,relations=relations,requirement_structures=structures)
            nodes = {node.semantic_id:node for node in graph.nodes}
            links = {(edge.source_id,edge.edge_type,edge.target_id) for edge in graph.edges}
            if arm:
                binding = requirement_binding(nodes['no_shell'].node_id,links=links,
                    node_types={node.node_id:node.node_type for node in graph.nodes},structures=graph.requirement_structures)
                if binding['operations']!={nodes['primary_operation'].node_id} or binding['subjects']:
                    raise ValueError('完整要求必须只约束主操作')
            flat = dict(facts=[dict(semantic_id=node.semantic_id,node_type=node.node_type,
                evidence_start=node.evidence_start,evidence_end=node.evidence_end,
                evidence_text=text[node.evidence_start:node.evidence_end]) for node in graph.nodes],
                relations=[dict(source=next(node.semantic_id for node in graph.nodes if node.node_id==edge.source_id),
                    relation=edge.edge_type,target=next(node.semantic_id for node in graph.nodes if node.node_id==edge.target_id))
                    for edge in graph.edges],requirement_structures=list(graph.requirement_structures))
            pair.append(dict(arm=arm,prompt=text,prompt_hash=content_hash(text),graph=prompt_tsg_record(graph),flat=flat,
                independent_representation_treatment=False))
        pre_graph = pair[0]['graph']
        by_semantic = {node['semantic_id']:node for node in pre_graph['nodes']}
        feature_position = int(by_semantic['primary_operation']['evidence_start']>
                               by_semantic['comparison_operation']['evidence_start'])
        evidence = pair[0]['prompt'][by_semantic['primary_operation']['evidence_start']:by_semantic['primary_operation']['evidence_end']]
        feature_reference = int(evidence==annotation['reference_operation'])
        gap = abs(by_semantic['primary_operation']['evidence_start']-by_semantic['primary_path']['evidence_start'])/len(base)
        versions.append(dict(version_id=f'position-{layout}-reference-{reference}',
            realization_factors=[feature_position,feature_reference],
            measured_graph_attributes=dict(normalized_binding_evidence_distance=gap,
                primary_mention_after_comparison=feature_position,
                role_reference_requires_declaration=feature_reference),arms=pair))
    contexts = []
    for c1,c2 in ((0,0),(0,1),(1,0),(1,1)):
        weights = []
        for version in versions:
            x,n = version['realization_factors']
            px,pn = .25+.5*c1,.25+.5*c2
            weights.append((px if x else 1-px)*(pn if n else 1-pn))
        contexts.append(dict(c1=c1,c2=c2,version_probabilities=weights))
    return dict(task_unit_id=source['task_unit_id'],family=source['family'],original_prompt_hash=source['prompt_hash'],
        catalog=catalog,versions=versions,contexts=contexts,role='preparation_only',
        representation_evaluation=dict(status='BLOCKED_MISSING_INDEPENDENT_REFERENCE_AND_MEASUREMENTS',
            version_factor_attributes=['primary_mention_after_comparison','role_reference_requires_declaration'],
            continuous_attribute_status='NOT_QUALIFIED_FOR_INTEGER_CI',
            independent_task_units=1,independent_representation_treatment=False),
        semantic_review='PENDING_INDEPENDENT_REVIEW',outcome_status='NOT_GENERATED',
        outcome_overlap_status='NOT_OBSERVED',automatic_graph_accuracy_established=False)


def source_span(text, quote, occurrence):
    if not isinstance(quote, str) or not quote or type(occurrence) is not int or occurrence < 0:
        raise ValueError('逐字来源引用或出现次数无效')
    start, offset = -1, 0
    for _ in range(occurrence + 1):
        start = text.find(quote, offset)
        if start < 0:
            raise ValueError('逐字引用没有对应来源位置')
        offset = start + 1
    return start, start + len(quote)


def apply_prepared_edits(text, edits):
    spans = []
    if not isinstance(edits, list) or not edits:
        raise ValueError('准备编辑必须提供非空替换列表')
    for edit in edits:
        if set(edit) != {'quote', 'occurrence', 'replacement'} or not isinstance(edit['replacement'], str):
            raise ValueError('准备编辑字段无效')
        start, stop = source_span(text, edit['quote'], edit['occurrence'])
        spans.append((start, stop, edit['replacement']))
    spans.sort()
    if any(left[1] > right[0] for left, right in zip(spans, spans[1:])):
        raise ValueError('准备编辑在原文中的范围重叠')
    result = text
    for start, stop, replacement in reversed(spans):
        result = result[:start] + replacement + result[stop:]
    if result == text:
        raise ValueError('准备编辑没有改变来源文本')
    return result


def prepare_requirement_removal(prompt, graph, catalog, feature_id, selector, protected_node_ids):
    from prompt_mechanism_study.tsg.prompt_tsg import (
        graph_requirement_membership, requirement_matches_policy, select_feature_scope,
        validate_prompt_tsg,
    )

    validate_prompt_tsg(graph, prompt=prompt, catalog=catalog)
    nodes = {node.node_id: node for node in graph.nodes}
    protected = set(protected_node_ids)
    if protected - set(nodes) or feature_id not in catalog['semantics']:
        raise ValueError('移除目标或保留证据不属于当前来源图形')
    result = dict(evidence_role='STRUCTURAL_PREPARATION_NOT_SEMANTIC_CERTIFICATION',
        semantic_review_required=True, status='unresolved', edits=[], requirement_node_ids=[])
    if feature_id in graph.unresolved_semantics or any(
        feature_id in (source,target) for source,_,target in graph.unresolved_relations
    ):
        return dict(result,reason='unresolved_target_semantics_or_relation')
    scope = select_feature_scope(graph,selector)
    if scope is None:
        return dict(result,reason='missing_or_ambiguous_complete_scope')
    asserted,_ = graph_requirement_membership(graph)
    requirements = [node for node in graph.nodes if node.node_id in asserted
        and node.semantic_id==feature_id and requirement_matches_policy(graph,node.node_id,scope,selector)]
    if not requirements:
        return dict(result,reason='missing_complete_requirement_occurrence')
    spans = sorted((node.evidence_start,node.evidence_end) for node in requirements)
    if any(left[1]>right[0] for left,right in zip(spans,spans[1:])):
        return dict(result,reason='overlapping_requirement_occurrences')
    # 语义归属不直接确定文本范围，保留证据与目标重叠时需要独立判断。
    conflicts = sorted(key for key in protected if any(
        start<nodes[key].evidence_end and nodes[key].evidence_start<stop for start,stop in spans))
    if conflicts:
        return dict(result,reason='target_span_overlaps_preserved_meaning',conflicting_node_ids=conflicts)
    references = nx.DiGraph((edge.source_id,edge.target_id) for edge in graph.edges if edge.edge_type=='refers_to')
    changed = {key for key,node in nodes.items() if any(
        start<node.evidence_end and node.evidence_start<stop for start,stop in spans)}
    dependencies = {key:sorted(nx.descendants(references,key)&changed) for key in sorted(protected)
        if references.has_node(key)}
    dependencies = {key:values for key,values in dependencies.items() if values}
    if dependencies:
        return dict(result,reason='preserved_reference_intersects_removed_evidence',reference_dependencies=dependencies)
    edits = []
    for start,stop in spans:
        quote = prompt[start:stop]
        if not quote:
            raise ValueError('完整要求的来源证据不能为空')
        occurrence,position = 0,prompt.find(quote)
        while 0<=position<start:
            occurrence += 1
            position = prompt.find(quote,position+1)
        if position!=start:
            raise ValueError('要求证据的位置与原始提示不符')
        edits.append(dict(quote=quote,occurrence=occurrence,replacement=''))
    edited = apply_prepared_edits(prompt,edits)
    return dict(result,status='prepared',reason='all_source_bound_complete_occurrences_removed',
        edits=edits,edited_prompt=edited,requirement_node_ids=sorted(node.node_id for node in requirements))


def prepare_expression_removal(prompt, graph, catalog, requirement_node_id, protected_node_ids,
                               *, equivalent_requirement_node_ids=(), assertion_edits=None):
    from prompt_mechanism_study.tsg.prompt_tsg import source_proposition_readback

    if not isinstance(equivalent_requirement_node_ids, (list, tuple)):
        raise ValueError('同一政策的其他来源出现必须使用明确节点列表')
    selected = [requirement_node_id, *equivalent_requirement_node_ids]
    view = source_proposition_readback(graph, selected, prompt=prompt, catalog=catalog)
    nodes = {node.node_id: node for node in graph.nodes}
    protected = set(protected_node_ids)
    if protected - set(nodes):
        raise ValueError('保留证据不属于当前来源图形')
    occurrences = {owner: {key for key, frame in view['propositions'].items()
        if owner in frame['expression_path_node_ids']} for owner in selected}
    owned = set().union(*occurrences.values())
    result = dict(status='unresolved', reason=None, edits=[],
        evidence_role='STRUCTURAL_EXPRESSION_PREPARATION_NOT_SEMANTIC_CERTIFICATION',
        semantic_review_required=True, whole_prompt_coverage_verified=False,
        policy_identity_review_required=len(selected) > 1, assertion_extent_review_required=assertion_edits is not None,
        requirement_node_id=requirement_node_id, equivalent_requirement_node_ids=list(equivalent_requirement_node_ids),
        expression_member_node_ids=sorted(owned), occurrence_members={key: sorted(value) for key, value in occurrences.items()},
        readback=view)
    for owner, members in occurrences.items():
        target = view['propositions'][owner]
        if not target['native_expression_asserted']:
            return dict(result, reason='unasserted_expression_member')
        if target['composition']['kind'] == 'and':
            return dict(result, reason='multiple_requirement_container')
        if any(view['propositions'][key]['composition']['kind'] in {'undeclared', 'opaque'} for key in members):
            return dict(result, reason='unresolved_complete_expression')
        if target['binding']['force'] != 'normative':
            return dict(result, reason='target_not_exclusively_normative')
        leaves = [view['propositions'][key] for key in members
                  if view['propositions'][key]['composition']['kind'] == 'atom']
        if not leaves or any(not frame['binding']['binding_complete'] for frame in leaves):
            return dict(result, reason='incomplete_expression_leaf_binding')
        if any(not nodes[owner].evidence_start <= nodes[key].evidence_start < nodes[key].evidence_end <= nodes[owner].evidence_end
               for key in members):
            return dict(result, reason='target_span_does_not_cover_complete_expression')
    semantics = {nodes[key].semantic_id for key in owned}
    if semantics & set(graph.unresolved_semantics) or any(
        source in semantics or endpoint in semantics for source, _, endpoint in graph.unresolved_relations
    ):
        return dict(result, reason='unresolved_target_semantics_or_relation')
    if assertion_edits is None:
        assertion_edits = []
        for owner in selected:
            start, stop = nodes[owner].evidence_start, nodes[owner].evidence_end
            quote, occurrence, position = prompt[start:stop], 0, prompt.find(prompt[start:stop])
            while position < start:
                if position < 0:
                    raise ValueError('完整表达式的证据位置不存在')
                occurrence += 1
                position = prompt.find(quote, position+1)
            if position != start:
                raise ValueError('完整表达式的证据位置不一致')
            assertion_edits.append(dict(owner_node_id=owner, quote=quote, occurrence=occurrence, replacement=''))
    if not isinstance(assertion_edits, list) or not assertion_edits:
        raise ValueError('断言编辑必须提供非空来源编辑列表')
    edits, spans, edited_owners = [], [], set()
    for edit in assertion_edits:
        if set(edit) != {'owner_node_id', 'quote', 'occurrence', 'replacement'} or edit['owner_node_id'] not in occurrences:
            raise ValueError('断言编辑没有绑定实际政策出现')
        owner = edit['owner_node_id']
        start, stop = source_span(prompt, edit['quote'], edit['occurrence'])
        if not nodes[owner].evidence_start <= start < stop <= nodes[owner].evidence_end:
            return dict(result, reason='assertion_edit_outside_occurrence_evidence')
        spans.append((start, stop))
        edited_owners.add(owner)
        edits.append({key: edit[key] for key in ('quote', 'occurrence', 'replacement')})
    if edited_owners != set(selected):
        return dict(result, reason='missing_assertion_edit_for_declared_occurrence')
    conditions = {row['source_node_id'] if row['edge_type'] == 'conditions' else row['target_node_id']
        for key in owned for row in view['propositions'][key]['expression_condition_attachments']
        if row['owner_node_id'] in owned}
    retained_conditions = {key for key in conditions
        if all(nodes[key].evidence_end <= start or nodes[key].evidence_start >= stop for start, stop in spans)}
    if any(not any(start <= nodes[key].evidence_start < nodes[key].evidence_end <= stop for start, stop in spans)
           for key in conditions - retained_conditions):
        return dict(result, reason='condition_evidence_partially_intersects_target_span')
    protected.update(retained_conditions)
    protected.update(key for key in view['propositions'] if key not in owned)
    protected.update(node.node_id for node in graph.nodes
        if node.node_type in {'task_requirement', 'safety_requirement', 'constraint', 'presentation_control'}
        and node.node_id not in owned)
    protected.update(edge.source_id for edge in graph.edges
        if edge.edge_type in {'conditions', 'context_for'} and edge.target_id not in owned)
    protected.update(edge.target_id for edge in graph.edges
        if edge.edge_type == 'under_condition' and edge.source_id not in owned)
    conflicts = sorted(key for key in protected
        if any(start < nodes[key].evidence_end and nodes[key].evidence_start < stop for start, stop in spans))
    if conflicts:
        return dict(result, reason='target_span_overlaps_preserved_meaning', conflicting_node_ids=conflicts)
    references = nx.DiGraph((edge.source_id, edge.target_id) for edge in graph.edges if edge.edge_type == 'refers_to')
    changed = {key for key, node in nodes.items()
        if any(start < node.evidence_end and node.evidence_start < stop for start, stop in spans)}
    dependencies = {key: sorted(nx.descendants(references, key) & changed) for key in sorted(protected)
        if references.has_node(key)}
    dependencies = {key: values for key, values in dependencies.items() if values}
    if dependencies:
        return dict(result, reason='preserved_reference_intersects_removed_evidence', reference_dependencies=dependencies)
    return dict(result, status='prepared', reason='declared_policy_assertion_edits_prepared', edits=edits,
        edited_prompt=apply_prepared_edits(prompt, edits), protected_node_ids=sorted(protected),
        assertion_edit_bindings=assertion_edits,
        source_unit_ids=sorted({key for owner in selected for key in view['nodes'][owner]['source_unit_ids']}),
        retained_condition_evidence={key: view['nodes'][key] for key in sorted(retained_conditions)},
        condition_scope_review_required=bool(retained_conditions))


def materialize_controlled_preparation(public, preparation):
    if preparation['task_id'] != public['task_id'] or preparation['flow'] != public['required_flow']:
        raise ValueError('准备任务或流程身份不匹配')
    originals = {row['version']: row['prompt'] for row in public['source_versions']}
    representation = preparation['representation']
    if preparation['flow'] == 'TSG':
        nodes = representation['nodes']
        identities = [node['id'] for node in nodes]
        if not nodes or len(set(identities)) != len(identities):
            raise ValueError('TSG 节点身份缺失或重复')
        for node in nodes:
            source_span(originals[node['version']], node['quote'], node['occurrence'])
        if not representation['edges'] or not representation['binding_queries']:
            raise ValueError('TSG 缺少关系或实际绑定查询')
        for edge in representation['edges']:
            if edge['source'] not in identities or edge['target'] not in identities or not edge['relation']:
                raise ValueError('TSG 关系引用无效')
    elif preparation['flow'] == 'Raw':
        if not isinstance(representation.get('analysis'), str) or not representation['analysis'].strip():
            raise ValueError('Raw 准备缺少来源分析')
    elif preparation['flow'] == 'Rich-Flat':
        if not isinstance(representation.get('facts'), list) or not representation['facts']:
            raise ValueError('Rich-Flat 准备缺少平面来源记录')
    else:
        raise ValueError('未规定的表示流程')
    rows = preparation['candidates']
    if len(rows) != 3 or {row['policy'] for row in rows} != set(POLICIES):
        raise ValueError('准备必须保留三个固定政策位置')
    candidates = []
    for row in rows:
        texts, failure = [], None
        if row['status'] == 'prepared':
            versions = row['versions']
            if len(versions) != len(originals) or {v['version'] for v in versions} != set(originals):
                failure = 'incomplete_expression_versions'
            else:
                for version in versions:
                    try:
                        edited = apply_prepared_edits(originals[version['version']], version['edits'])
                    except ValueError as error:
                        failure = str(error)
                        break
                    texts.append(dict(version=version['version'], original=originals[version['version']],
                                      edited=edited, original_sha256=content_hash(originals[version['version']]),
                                      edited_sha256=content_hash(edited)))
        elif row['status'] == 'unprepared':
            failure = row.get('reason', 'declared_unprepared')
        else:
            raise ValueError('准备状态未定义')
        candidates.append(dict(policy=row['policy'], mechanical_status='failed' if failure else 'materialized',
                               failure_reason=failure, versions=[] if failure else texts))
    return dict(task_id=public['task_id'], candidates=candidates)


def submit_controlled_preparation(public_path: Path, submission: Path, output: Path):
    public, record = read_json_exact(public_path), read_json_exact(submission)
    materialized = materialize_controlled_preparation(public, record)
    for original, candidate in zip(record['candidates'], materialized['candidates'], strict=True):
        if original['status'] == 'prepared' and candidate['mechanical_status'] != 'materialized':
            raise ValueError(f'准备尚未完整提交: {candidate["policy"]}: {candidate["failure_reason"]}')
        if original['status'] == 'unprepared' and not original.get('reason'):
            raise ValueError('未完成的候选必须记录具体原因')
    write_json_new(output, record)
    return dict(task_id=public['task_id'], status='SUBMITTED', output=str(output), sha256=file_sha256(output))


def submit_controlled_review(input_path: Path, submission: Path, output: Path):
    source, record = read_json_exact(input_path), read_json_exact(submission)
    reviews = record['reviews']
    if record['task_id'] != source['task_id'] or len(reviews) != 3 or {row['policy'] for row in reviews} != set(POLICIES):
        raise ValueError('检查提交缺少完整政策位置或任务身份不符')
    candidates = {row['policy']: row for row in source['candidates']}
    for review in reviews:
        if review['status'] not in ('pass', 'fail', 'unknown'):
            raise ValueError('检查状态无效')
        candidate = candidates[review['policy']]
        if candidate['mechanical_status'] == 'failed':
            if review['status'] != 'fail' or review['versions'] or not review.get('reason'):
                raise ValueError('机械失败必须保留失败与具体原因')
            continue
        expected = {row['version'] for row in candidate['versions']}
        versions = review['versions']
        if len(versions) != len(expected) or {row['version'] for row in versions} != expected:
            raise ValueError('检查尚未提交全部实际表达版本')
        for version in versions:
            if version['status'] not in ('pass', 'fail', 'unknown') or not version.get('reason'):
                raise ValueError('逐版本检查缺少状态或依据')
            if any(len(version[key]) != 3 or any(value is not None and (type(value) is not int or value not in (0, 1))
                   for value in version[key]) for key in ('states_before', 'states_after')):
                raise ValueError('检查状态必须保留三个位置及必要未知')
            if version['status'] == 'pass' and (version['binding_preserved'] is not True
                    or version['non_target_preserved'] is not True
                    or None in version['states_before'] or None in version['states_after']):
                raise ValueError('通过检查缺少确定的绑定、状态或非目标保持')
            if version['status'] == 'pass':
                expected_after = list(version['states_before'])
                position = POLICIES.index(review['policy'])
                expected_after[position] = 1 - expected_after[position]
                if version['states_after'] != expected_after:
                    raise ValueError('通过检查必须仅翻转目标政策状态')
        if review['status'] == 'pass' and any(row['status'] != 'pass' for row in versions):
            raise ValueError('候选通过状态与逐版本状态不一致')
    write_json_new(output, record)
    return dict(task_id=source['task_id'], status='SUBMITTED', output=str(output), sha256=file_sha256(output))
