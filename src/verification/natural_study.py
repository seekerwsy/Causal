"""Independent verifier for offline natural-task Stage I -> Stage II studies."""

from __future__ import annotations

import ast
import hashlib
import zipfile
from pathlib import Path

import numpy as np
from markdown_it import MarkdownIt
from scipy.stats import t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle, write_bundle
from prompt_mechanism_study.measurement.security_profiles import evaluate_security_profile
from prompt_mechanism_study.tsg.prompt_contract import compile_source_propositions
from prompt_mechanism_study.tsg.source_representation import (
    TSG_BINARY_ATTRIBUTE_NAMES,
    extract_tsg_structural_attributes,
)
from prompt_mechanism_study.verification.assignment import verify_fold_nested_assignment
from prompt_mechanism_study.verification.prognostic_learning import (
    _independent_roles,
    _verify_ci_queries,
    verify_source_and_cross_fit_records,
)


def _independent_splice(scaffold_code: str, response_text: str, target_symbol: str | None) -> tuple[str, str | None]:
    if not isinstance(response_text, str) or not response_text.strip():
        return 'no_code', None
    blocks = [tok for tok in MarkdownIt('commonmark').parse(response_text) if tok.type in ('fence', 'code_block')]
    if len(blocks) > 1:
        return 'invalid', None
    if blocks:
        if blocks[0].type == 'fence' and blocks[0].info.strip().lower() not in ('', 'python', 'py'):
            return 'invalid', None
        raw = blocks[0].content
    else:
        raw = response_text
    if raw.lstrip().startswith(('diff --git ', '--- a/', '*** Begin Patch')) or not raw.strip():
        return ('no_code' if not raw.strip() else 'invalid'), None
    norm_raw = raw.replace('\r\n', '\n').replace('\r', '\n')
    try:
        cand_tree = ast.parse(norm_raw)
    except SyntaxError:
        return 'invalid', None
    if target_symbol is None:
        return 'valid', norm_raw.rstrip('\n') + '\n'
    scaf_norm = scaffold_code.replace('\r\n', '\n').replace('\r', '\n')
    scaf_tree = ast.parse(scaf_norm)
    scaf_fn = [n for n in scaf_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == target_symbol]
    cand_fn = [n for n in cand_tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == target_symbol]
    assert len(scaf_fn) == 1
    if len(cand_fn) != 1:
        return 'invalid', None
    s0 = min([scaf_fn[0].lineno, *(d.lineno for d in scaf_fn[0].decorator_list)]) - 1
    c0 = min([cand_fn[0].lineno, *(d.lineno for d in cand_fn[0].decorator_list)]) - 1
    lines = [*scaf_norm.splitlines()[:s0], *norm_raw.splitlines()[c0:cand_fn[0].end_lineno], *scaf_norm.splitlines()[scaf_fn[0].end_lineno:]]
    spliced = '\n'.join(lines).rstrip('\n') + '\n'
    try:
        ast.parse(spliced)
    except SyntaxError:
        return 'invalid', None
    return 'valid', spliced


def _independent_endpoint_summary(rows: list[dict]) -> dict:
    n = len(rows)
    assert n > 0
    valid = sum(row['code_valid'] for row in rows)
    evaluable = sum(row['oracle_evaluable'] for row in rows)
    secure = sum(row['secure_yield'] for row in rows)
    unknown_oracle = sum(1 for row in rows if row['code_valid'] == 1 and row['oracle_evaluable'] == 0)
    func_pass = sum(1 for row in rows if row['functionality'] == 1)
    func_fail = sum(1 for row in rows if row['functionality'] == 0 and row['code_valid'] == 1)
    func_unknown = sum(1 for row in rows if row['functionality'] is None)
    joint_pass = sum(1 for row in rows if row['joint'] == 1)
    joint_unknown = sum(1 for row in rows if row['joint'] is None)
    return dict(
        assigned_n=n,
        code_valid_count=valid,
        code_valid_rate=valid / n,
        oracle_evaluable_count=evaluable,
        oracle_evaluable_rate=evaluable / n,
        secure_yield_count=secure,
        secure_yield_rate=secure / n,
        unknown_oracle_count=unknown_oracle,
        unknown_oracle_rate=unknown_oracle / n,
        functional_pass_count=func_pass,
        functional_fail_count=func_fail,
        functional_unknown_count=func_unknown,
        functional_pass_rate=func_pass / n,
        joint_pass_count=joint_pass,
        joint_unknown_count=joint_unknown,
        joint_rate=joint_pass / n,
        latent_secure_upper_rate=sum(row['latent_secure_upper'] for row in rows) / n,
        latent_joint_upper_rate=sum(row['latent_joint_upper'] for row in rows) / n,
    )


def _check_measurement_rows(items, arm_fn, response_fn, func_fn, rows):
    assert len(items) == len(rows)
    for item, row in zip(items, rows):
        assert row['task_unit_id'] == item['task_unit_id']
        arm = arm_fn(item)
        assert row['arm'] == arm
        status, spliced = _independent_splice(
            item['scaffold_code'], response_fn(item, arm), item.get('target_symbol')
        )
        assert row['code_status'] == status
        if status != 'valid':
            assert row['spliced_code'] is None and row['code_sha256'] is None
            assert (row['code_valid'], row['oracle_evaluable'], row['secure_yield']) == (0, 0, 0)
            assert row['latent_secure_upper'] == 0 and row['functionality'] == 0 and row['joint'] == 0
        else:
            assert row['spliced_code'] == spliced
            assert row['code_sha256'] == hashlib.sha256(spliced.encode('utf-8')).hexdigest()
            sec = evaluate_security_profile(spliced, item['oracle_profile_id'])
            assert row['oracle_status'] == sec['security_label']
            assert row['functional_status'] == func_fn(item, arm)
            expected_eval = int(sec['security_label'] in ('secure', 'insecure'))
            expected_sec = int(sec['security_label'] == 'secure')
            assert row['code_valid'] == 1
            assert row['oracle_evaluable'] == expected_eval
            assert row['secure_yield'] == expected_sec
            if sec['security_label'] == 'unknown':
                # Never coerce unknown oracle results into insecure or absent.
                assert row['oracle_evaluable'] == 0 and row['secure_yield'] == 0
                assert row['latent_secure_upper'] == 1 and row['joint'] is None


def verify_natural_study(output_dir: Path) -> dict:
    output = Path(output_dir)
    for part in ('inputs', 'stage1', 'assignment', 'measurements', 'stage2', 'summary'):
        verify_bundle(output / part)

    plan = read_json(output / 'inputs' / 'plan.json')
    identity = read_json(output / 'inputs' / 'identity.json')
    fixture = read_json(output / 'inputs' / 'fixture.json')
    stage1 = read_json(output / 'stage1' / 'result.json')
    assignment = read_json(output / 'assignment' / 'result.json')
    measurements = read_json(output / 'measurements' / 'result.json')
    stage2 = read_json(output / 'stage2' / 'result.json')
    summary = read_json(output / 'summary' / 'result.json')

    assert plan.get('formal_claim_allowed') is False and plan.get('new_provider_calls', 0) == 0
    assert summary.get('formal_claim_allowed') is False and summary.get('new_provider_calls', 0) == 0
    assert file_sha256(output / 'source.zip') == identity['source_archive_sha256']
    with zipfile.ZipFile(output / 'source.zip') as archive:
        for path, digest in identity['sources'].items():
            assert hashlib.sha256(archive.read(path)).hexdigest() == digest

    # Replay Stage I extraction and reliability gate independently.
    target_units = sorted(fixture['target'], key=lambda row: row['task_unit_id'])
    n_contexts = len(plan['context_names'])
    for cohort_key, ext_id, cohort_items in (
        ('auxiliary', 'natural-stage1-aux', fixture['auxiliary']),
        ('source', 'natural-stage1-src', fixture['source']),
        ('target', 'natural-stage1-tgt', target_units),
    ):
        recorded = stage1[cohort_key]
        assert len(recorded) == len(cohort_items)
        expected_mat = []
        for item, rec in zip(cohort_items, recorded):
            g, comp = compile_source_propositions(item['task'], item['record'], extractor_id=ext_id)
            ids = comp['local_node_ids']
            t_cfg = item.get('target', {})
            attrs = extract_tsg_structural_attributes(
                g,
                operation_node_id=ids[t_cfg['operation_local_id']] if t_cfg.get('operation_local_id') else None,
                requirement_node_id=ids[t_cfg['requirement_local_id']] if t_cfg.get('requirement_local_id') else None,
                prompt=item['task']['prompt'],
                catalog=comp['catalog'],
            )
            assert rec['binary_structural_vector'] == attrs['binary_structural_vector']
            assert rec['tsg_id'] == attrs['tsg_id']
            expected_mat.append([*item['context'], *attrs['binary_structural_vector']])
        assert stage2['data'][cohort_key]['x'] == expected_mat

    ref_mat, cand_mat = [], []
    for entry in fixture['reliability_audit']:
        t_cfg = entry.get('target', {})
        g1, c1 = compile_source_propositions(entry['task'], entry['record_ref'], extractor_id='verify-audit-ref')
        g2, c2 = compile_source_propositions(entry['task'], entry['record_cand'], extractor_id='verify-audit-cand')
        ids1, ids2 = c1['local_node_ids'], c2['local_node_ids']
        a1 = extract_tsg_structural_attributes(
            g1, operation_node_id=ids1[t_cfg['operation_local_id']],
            requirement_node_id=ids1[t_cfg['requirement_local_id']],
            prompt=entry['task']['prompt'], catalog=c1['catalog'],
        )
        a2 = extract_tsg_structural_attributes(
            g2, operation_node_id=ids2[t_cfg['operation_local_id']],
            requirement_node_id=ids2[t_cfg['requirement_local_id']],
            prompt=entry['task']['prompt'], catalog=c2['catalog'],
        )
        ref_mat.append(a1['binary_structural_vector'])
        cand_mat.append(a2['binary_structural_vector'])
    rates = np.mean(np.asarray(ref_mat) != np.asarray(cand_mat), axis=0)
    median_flip = float(np.median(rates))
    np.testing.assert_allclose(stage1['reliability']['flip_rates'], rates.tolist(), atol=1e-12)
    np.testing.assert_allclose(stage1['reliability']['median_flip_rate'], median_flip, atol=1e-12)
    stable = [i for i, r in enumerate(rates.tolist()) if r <= plan['max_attribute_flip_rate']]
    expected_gate = bool(median_flip <= plan['max_median_flip_rate'] and len(stable) >= 1)
    assert stage1['reliability']['gate_passed'] == expected_gate

    # Replay D1 fold-nested assignment and verify full ITT denominator.
    verified_assign = verify_fold_nested_assignment(assignment)
    assert verified_assign['units'] == len(target_units)
    assign_map = {row['task_unit_id']: row for row in assignment['assignments']}
    assert set(assign_map) == {u['task_unit_id'] for u in target_units}

    _check_measurement_rows(
        fixture['source'],
        lambda it: int(it['arm']),
        lambda it, arm: it['response_text'],
        lambda it, arm: it['functional_status'],
        measurements['source'],
    )
    _check_measurement_rows(
        target_units,
        lambda it: int(assign_map[it['task_unit_id']]['arm']),
        lambda it, arm: it['arm_responses'][str(arm)],
        lambda it, arm: it['arm_functional_status'][str(arm)],
        measurements['target'],
    )
    assert stage2['data']['source']['y'] == [row['secure_yield'] for row in measurements['source']]
    assert stage2['data']['target']['y'] == [row['secure_yield'] for row in measurements['target']]
    assert stage2['data']['target']['a'] == [int(assign_map[u['task_unit_id']]['arm']) for u in target_units]

    # Replay CI queries, PAG roles, source KKT, and target cross-fitting.
    labels = [*plan['context_names'], *TSG_BINARY_ATTRIBUTE_NAMES]
    _verify_ci_queries(
        stage2['queries'],
        np.asarray(stage2['data']['auxiliary']['x']),
        labels,
        plan['ci_draws'],
        plan['ci_seed'],
    )
    roles = _independent_roles(
        stage2['graph'],
        n_contexts=n_contexts,
        n_attributes=len(TSG_BINARY_ATTRIBUTE_NAMES),
    )
    assert stage2['roles']['eligible'] == roles['eligible']
    assert stage2['roles']['root'] == roles['root']
    assert stage2['roles']['terminal'] == roles['terminal']
    assert stage2['roles']['upstream'] == roles['upstream']
    assert stage2['roles']['other'] == roles['other']

    verify_source_and_cross_fit_records(
        stage2['source']['models'],
        stage2['cross_fit'],
        src_x=np.asarray(stage2['data']['source']['x']),
        src_y=np.asarray(stage2['data']['source']['y'], dtype=float),
        tgt_x=np.asarray(stage2['data']['target']['x']),
        tgt_a=np.asarray(stage2['data']['target']['a']),
        tgt_y=np.asarray(stage2['data']['target']['y'], dtype=float),
        fit_seed=plan['fit_seed'],
        k_folds=plan['target_folds'],
    )

    # Recompute all summary endpoints, intervals, and guidance statuses from raw rows.
    tgt_rows = measurements['target']
    expected_ep = dict(
        arm_0=_independent_endpoint_summary([r for r in tgt_rows if r['arm'] == 0]),
        arm_1=_independent_endpoint_summary([r for r in tgt_rows if r['arm'] == 1]),
        overall=_independent_endpoint_summary(tgt_rows),
    )
    assert summary['assigned_n'] == len(target_units) == expected_ep['overall']['assigned_n']
    assert summary['reliability_gate_passed'] == expected_gate
    np.testing.assert_allclose(summary['median_attribute_flip_rate'], median_flip, atol=1e-12)
    assert summary['direction_eligible'] == roles['eligible']
    assert summary['endpoints'] == expected_ep
    func_delta = expected_ep['arm_1']['functional_pass_rate'] - expected_ep['arm_0']['functional_pass_rate']
    np.testing.assert_allclose(summary['functionality_itt_delta'], func_delta, atol=1e-12)

    t_crit = float(t.ppf(1.0 - plan['component_alpha'] / 2.0, len(target_units) - 1))
    margin = float(plan['practical_margin'])
    for method, cf in stage2['cross_fit'].items():
        rec = summary['effect_estimates'][method]
        est, se = float(cf['effect']), float(cf['standard_error'])
        low, high = est - t_crit * se, est + t_crit * se
        np.testing.assert_allclose(rec['effect'], est, atol=1e-12)
        np.testing.assert_allclose(rec['standard_error'], se, atol=1e-12)
        np.testing.assert_allclose(rec['interval'], [low, high], atol=1e-12)
        if low > margin:
            expected_status = 'positive_hardening' if func_delta >= -margin else 'positive_hardening_with_functional_tradeoff'
        elif high < -margin:
            expected_status = 'adverse_warning'
        elif low >= -margin and high <= margin:
            expected_status = 'practically_null'
        else:
            expected_status = 'inconclusive'
        assert rec['guidance_status'] == expected_status
    assert summary['jci_guidance_status'] == summary['effect_estimates']['jci']['guidance_status']
    np.testing.assert_allclose(summary['jci_effect'], summary['effect_estimates']['jci']['effect'], atol=1e-12)
    np.testing.assert_allclose(summary['jci_standard_error'], summary['effect_estimates']['jci']['standard_error'], atol=1e-12)

    result = dict(
        status='VERIFIED',
        study_id=plan['study_id'],
        study_mode='natural_task',
        assigned_n=len(target_units),
        reliability_gate_passed=expected_gate,
        queries_verified=len(stage2['queries']),
        direction_eligible=roles['eligible'],
        jci_guidance_status=summary['jci_guidance_status'],
        summary_sha256=file_sha256(output / 'summary' / 'result.json'),
    )
    write_bundle(output / 'verification', {'result.json': result})
    return result
