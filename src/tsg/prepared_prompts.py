from __future__ import annotations

from pathlib import Path

from prompt_mechanism_study.artifact_io import file_sha256, read_json_exact, write_json_new
from prompt_mechanism_study.records import content_hash


POLICIES = ('local', 'example', 'reference')


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
