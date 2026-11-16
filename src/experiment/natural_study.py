"""Offline and provider-free natural-task Stage I -> Stage II end-to-end study runner."""

from __future__ import annotations

import platform
import zipfile
from pathlib import Path
from typing import Any, Mapping

import numpy as np
import scipy
import sklearn
from scipy.stats import t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_bundle
from prompt_mechanism_study.discovery.prognostic_learning import discover_and_fit_stage2
from prompt_mechanism_study.experiment.assignment import assign_fold_nested
from prompt_mechanism_study.experiment.code_generation import splice_target_unit_code
from prompt_mechanism_study.experiment.outcomes import Outcome, derive_outcomes
from prompt_mechanism_study.measurement.evaluate import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    MeasurementLedger,
    OracleStatus,
)
from prompt_mechanism_study.measurement.security_profiles import evaluate_security_profile
from prompt_mechanism_study.records import content_hash
from prompt_mechanism_study.tsg.prompt_contract import compile_source_propositions
from prompt_mechanism_study.tsg.source_representation import (
    TSG_BINARY_ATTRIBUTE_NAMES,
    evaluate_binary_attribute_reliability,
    extract_tsg_structural_attributes,
)

SOURCE_FILES = (
    'src/experiment/natural_study.py',
    'src/verification/natural_study.py',
    'src/discovery/prognostic_learning.py',
    'src/discovery/jci_structure.py',
    'src/discovery/jci_context.R',
    'src/experiment/assignment.py',
    'src/verification/assignment.py',
    'src/verification/prognostic_learning.py',
    'src/experiment/code_generation.py',
    'src/experiment/outcomes.py',
    'src/measurement/evaluate.py',
    'src/measurement/security_profiles.py',
    'src/tsg/prompt_contract.py',
    'src/tsg/prompt_tsg.py',
    'src/tsg/source_representation.py',
    'src/artifact_io.py',
    'src/records.py',
    'src/cli.py',
    'pyproject.toml',
)


def validate_natural_plan(plan: Mapping[str, Any]) -> None:
    if plan.get('formal_claim_allowed') is not False or plan.get('new_provider_calls', 0) != 0:
        raise ValueError('Natural study plan must keep formal_claim_allowed=false and new_provider_calls=0')
    if plan.get('study_mode') != 'natural_task':
        raise ValueError('Natural study plan requires study_mode == "natural_task"')
    if len(plan.get('context_names', [])) < 1:
        raise ValueError('Natural study plan requires at least one declared context name')
    if type(plan.get('target_folds', 0)) is not int or plan.get('target_folds', 0) < 2:
        raise ValueError('Natural study plan requires integer target_folds >= 2')
    if any(p <= 0 for p in plan.get('correction_penalties', [])) or any(p <= 0 for p in plan.get('inverse_penalties', [])):
        raise ValueError('All regularization penalties must be strictly positive')
    if any(s < 0 for s in plan.get('structure_strengths', [])):
        raise ValueError('Structure penalty strengths must be non-negative')
    if plan.get('maximum_skeleton_conditioning_order', 0) < 1 or not 0 < plan.get('component_alpha', 0) < 1:
        raise ValueError('Invalid conditioning order or component_alpha')
    if plan.get('practical_margin', 0) <= 0:
        raise ValueError('practical_margin must be strictly positive')
    if not plan.get('fixture_path'):
        raise ValueError('Natural study plan requires fixture_path')


def _extract_cohort_stage1(items: list[dict[str, Any]], *, extractor_id: str, n_contexts: int):
    rows = []
    matrix = []
    for item in items:
        ctx = [int(v) for v in item['context']]
        if len(ctx) != n_contexts or any(v not in (0, 1) for v in ctx):
            raise ValueError(f'Task {item["task_unit_id"]} context does not match {n_contexts} binary contexts')
        graph, compiled = compile_source_propositions(item['task'], item['record'], extractor_id=extractor_id)
        ids = compiled['local_node_ids']
        tgt = item.get('target', {})
        op_id = ids[tgt['operation_local_id']] if tgt.get('operation_local_id') else None
        req_id = ids[tgt['requirement_local_id']] if tgt.get('requirement_local_id') else None
        attrs = extract_tsg_structural_attributes(
            graph,
            operation_node_id=op_id,
            requirement_node_id=req_id,
            prompt=item['task']['prompt'],
            catalog=compiled['catalog'],
        )
        bvec = [int(v) for v in attrs['binary_structural_vector']]
        rows.append(
            dict(
                task_unit_id=item['task_unit_id'],
                tsg_id=attrs['tsg_id'],
                context=ctx,
                binary_structural_vector=bvec,
                structural_vector=attrs['structural_vector'],
                local_binding_complete=bool(attrs['local_binding_complete']),
                local_unresolved_count=int(attrs['local_unresolved_count']),
            )
        )
        matrix.append([*ctx, *bvec])
    return rows, matrix


def _measure_item(
    *,
    assignment_id: str,
    task_unit_id: str,
    arm: int,
    scaffold_code: str,
    target_symbol: str | None,
    oracle_profile_id: str,
    response_text: str,
    functional_status: str,
) -> tuple[Measurement, dict[str, Any]]:
    splice = splice_target_unit_code(scaffold_code, response_text, target_symbol=target_symbol)
    gen_digest = content_hash(response_text)
    if splice['code_status'] != 'valid':
        code_status = CodeStatus(splice['code_status'])
        measurement = Measurement(
            assignment_id,
            code_status,
            OracleStatus.NOT_RUN,
            FunctionalStatus.NOT_RUN,
            gen_digest,
            terminal_reason=str(splice['terminal_reason'] or code_status.value),
        )
        detail = dict(
            assignment_id=assignment_id,
            task_unit_id=task_unit_id,
            arm=arm,
            code_status=code_status.value,
            terminal_reason=splice['terminal_reason'],
            oracle_status=OracleStatus.NOT_RUN.value,
            functional_status=FunctionalStatus.NOT_RUN.value,
            code_sha256=None,
            spliced_code=None,
        )
        return measurement, detail

    spliced_code = str(splice['spliced_code'])
    sec = evaluate_security_profile(spliced_code, oracle_profile_id)
    oracle = OracleStatus(sec['security_label'])
    func = FunctionalStatus(functional_status)
    func_digest = content_hash({'assignment_id': assignment_id, 'functional_status': func.value})
    measurement = Measurement(
        assignment_id,
        CodeStatus.VALID,
        oracle,
        func,
        gen_digest,
        str(splice['code_sha256']),
        content_hash(sec),
        func_digest,
    )
    detail = dict(
        assignment_id=assignment_id,
        task_unit_id=task_unit_id,
        arm=arm,
        code_status=CodeStatus.VALID.value,
        terminal_reason=None,
        oracle_profile_id=oracle_profile_id,
        oracle_status=oracle.value,
        functional_status=func.value,
        code_sha256=splice['code_sha256'],
        oracle_evidence_sha256=content_hash(sec),
        spliced_code=spliced_code,
    )
    return measurement, detail


def _arm_endpoint_summary(rows: list[tuple[int, Outcome]]) -> dict[str, Any]:
    n = len(rows)
    if n == 0:
        raise ValueError('Endpoint denominator cannot be empty')
    outs = [outcome for _, outcome in rows]
    valid = sum(o.code_valid for o in outs)
    evaluable = sum(o.oracle_evaluable for o in outs)
    secure = sum(o.secure_yield for o in outs)
    unknown_oracle = sum(1 for o in outs if o.code_valid == 1 and o.oracle_evaluable == 0)
    func_pass = sum(1 for o in outs if o.functionality == 1)
    func_fail = sum(1 for o in outs if o.functionality == 0 and o.code_valid == 1)
    func_unknown = sum(1 for o in outs if o.functionality is None)
    joint_pass = sum(1 for o in outs if o.joint == 1)
    joint_unknown = sum(1 for o in outs if o.joint is None)
    latent_sec_upper = sum(o.latent_secure_upper for o in outs)
    latent_joint_upper = sum(o.latent_joint_upper for o in outs)
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
        latent_secure_upper_rate=latent_sec_upper / n,
        latent_joint_upper_rate=latent_joint_upper / n,
    )


def classify_scoped_guidance(
    ci_low: float,
    ci_high: float,
    practical_margin: float,
    functionality_delta: float,
) -> str:
    if ci_low > practical_margin:
        return 'positive_hardening' if functionality_delta >= -practical_margin else 'positive_hardening_with_functional_tradeoff'
    if ci_high < -practical_margin:
        return 'adverse_warning'
    if ci_low >= -practical_margin and ci_high <= practical_margin:
        return 'practically_null'
    return 'inconclusive'


def run_natural_study(plan_path: Path, output_dir: Path, *, rscript: Path | None = None) -> dict[str, Any]:
    plan_file = Path(plan_path)
    plan = read_json(plan_file)
    validate_natural_plan(plan)

    fixture_file = Path(plan['fixture_path'])
    fixture = read_json(fixture_file)
    context_names = list(plan['context_names'])
    if list(fixture.get('context_names', [])) != context_names:
        raise ValueError('Plan context_names do not match fixture context_names')
    n_contexts = len(context_names)

    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=False)

    sources = [Path(name) for name in SOURCE_FILES]
    with zipfile.ZipFile(output / 'source.zip', 'x', compression=zipfile.ZIP_DEFLATED) as archive:
        for src in sources:
            archive.write(src, src.as_posix())

    target_units = sorted(fixture['target'], key=lambda row: row['task_unit_id'])
    n_target = len(target_units)
    if n_target < plan['target_folds']:
        raise ValueError('Target units must be >= target_folds')

    write_bundle(
        output / 'inputs',
        {
            'plan.json': plan,
            'fixture.json': fixture,
            'identity.json': dict(
                source_archive_sha256=file_sha256(output / 'source.zip'),
                fixture_sha256=file_sha256(fixture_file),
                sources={path.as_posix(): file_sha256(path) for path in sources},
                python=platform.python_version(),
                numpy=np.__version__,
                scipy=scipy.__version__,
                sklearn=sklearn.__version__,
                backend='native' if rscript is None else str(rscript),
                n_auxiliary=len(fixture['auxiliary']),
                n_source=len(fixture['source']),
                n_target=n_target,
            ),
        },
    )

    # Stage I: compile Prompt TSGs and extract 16-dim binary vectors + pre-outcome reliability check.
    aux_rows, aux_x = _extract_cohort_stage1(fixture['auxiliary'], extractor_id='natural-stage1-aux', n_contexts=n_contexts)
    src_rows, src_x = _extract_cohort_stage1(fixture['source'], extractor_id='natural-stage1-src', n_contexts=n_contexts)
    tgt_rows, tgt_x = _extract_cohort_stage1(target_units, extractor_id='natural-stage1-tgt', n_contexts=n_contexts)

    audit_ref_vecs, audit_cand_vecs, audit_pairs = [], [], []
    for entry in fixture['reliability_audit']:
        t_cfg = entry.get('target', {})
        g_ref, c_ref = compile_source_propositions(entry['task'], entry['record_ref'], extractor_id='natural-audit-ref')
        g_cand, c_cand = compile_source_propositions(entry['task'], entry['record_cand'], extractor_id='natural-audit-cand')
        ids_r, ids_c = c_ref['local_node_ids'], c_cand['local_node_ids']
        a_ref = extract_tsg_structural_attributes(
            g_ref,
            operation_node_id=ids_r[t_cfg['operation_local_id']] if t_cfg.get('operation_local_id') else None,
            requirement_node_id=ids_r[t_cfg['requirement_local_id']] if t_cfg.get('requirement_local_id') else None,
            prompt=entry['task']['prompt'],
            catalog=c_ref['catalog'],
        )
        a_cand = extract_tsg_structural_attributes(
            g_cand,
            operation_node_id=ids_c[t_cfg['operation_local_id']] if t_cfg.get('operation_local_id') else None,
            requirement_node_id=ids_c[t_cfg['requirement_local_id']] if t_cfg.get('requirement_local_id') else None,
            prompt=entry['task']['prompt'],
            catalog=c_cand['catalog'],
        )
        audit_ref_vecs.append(a_ref['binary_structural_vector'])
        audit_cand_vecs.append(a_cand['binary_structural_vector'])
        audit_pairs.append(dict(task_unit_id=entry['task_unit_id'], ref_tsg_id=a_ref['tsg_id'], cand_tsg_id=a_cand['tsg_id']))

    reliability = evaluate_binary_attribute_reliability(
        audit_ref_vecs,
        audit_cand_vecs,
        attribute_names=TSG_BINARY_ATTRIBUTE_NAMES,
        max_median_flip_rate=plan['max_median_flip_rate'],
        max_attribute_flip_rate=plan['max_attribute_flip_rate'],
    )
    write_bundle(
        output / 'stage1',
        {
            'result.json': dict(
                context_names=context_names,
                attribute_names=list(TSG_BINARY_ATTRIBUTE_NAMES),
                auxiliary=aux_rows,
                source=src_rows,
                target=tgt_rows,
                reliability_audit=audit_pairs,
                reliability=reliability,
            )
        },
    )

    # Fold-nested randomized assignment (Design condition D1).
    assignment = assign_fold_nested(
        [unit['task_unit_id'] for unit in target_units],
        folds=plan['target_folds'],
        seed=plan['assignment_seed'],
    )
    write_bundle(output / 'assignment', {'result.json': assignment})

    # Measurement & endpoint decomposition (zero filtering; unknown never coerced).
    src_measurements, src_details = [], []
    src_arms, src_y = [], []
    for item in fixture['source']:
        arm = int(item['arm'])
        if arm not in (0, 1):
            raise ValueError('Source arm must be 0 or 1')
        aid = f'src_{item["task_unit_id"]}'
        meas, det = _measure_item(
            assignment_id=aid,
            task_unit_id=item['task_unit_id'],
            arm=arm,
            scaffold_code=item['scaffold_code'],
            target_symbol=item.get('target_symbol'),
            oracle_profile_id=item['oracle_profile_id'],
            response_text=item['response_text'],
            functional_status=item['functional_status'],
        )
        src_measurements.append(meas)
        src_details.append(det)
        src_arms.append(arm)
    src_ledger = MeasurementLedger(plan['study_id'], 'historical-source', 'local-ast-profile-v2', tuple(src_measurements))
    src_outcomes = {o.assignment_id: o for o in derive_outcomes(src_ledger)}
    src_y = [src_outcomes[f'src_{item["task_unit_id"]}'].secure_yield for item in fixture['source']]

    tgt_measurements, tgt_details = [], []
    tgt_arms = []
    assign_map = {row['task_unit_id']: row for row in assignment['assignments']}
    for unit in target_units:
        uid = unit['task_unit_id']
        arm = int(assign_map[uid]['arm'])
        aid = f'tgt_{uid}'
        meas, det = _measure_item(
            assignment_id=aid,
            task_unit_id=uid,
            arm=arm,
            scaffold_code=unit['scaffold_code'],
            target_symbol=unit.get('target_symbol'),
            oracle_profile_id=unit['oracle_profile_id'],
            response_text=unit['arm_responses'][str(arm)],
            functional_status=unit['arm_functional_status'][str(arm)],
        )
        tgt_measurements.append(meas)
        tgt_details.append(det)
        tgt_arms.append(arm)
    tgt_ledger = MeasurementLedger(plan['study_id'], assignment['schema'], 'local-ast-profile-v2', tuple(tgt_measurements))
    tgt_outcomes_map = {o.assignment_id: o for o in derive_outcomes(tgt_ledger)}
    tgt_y = [tgt_outcomes_map[f'tgt_{u["task_unit_id"]}'].secure_yield for u in target_units]

    def _outcome_row(det, outcomes_map):
        out = outcomes_map[det['assignment_id']]
        return {
            **det,
            'code_valid': out.code_valid,
            'oracle_evaluable': out.oracle_evaluable,
            'secure_yield': out.secure_yield,
            'latent_secure_upper': out.latent_secure_upper,
            'functionality': out.functionality,
            'joint': out.joint,
            'latent_joint_upper': out.latent_joint_upper,
        }

    write_bundle(
        output / 'measurements',
        {
            'result.json': dict(
                source=[_outcome_row(det, src_outcomes) for det in src_details],
                target=[_outcome_row(det, tgt_outcomes_map) for det in tgt_details],
            )
        },
    )

    # Stage II: JCI-12 PAG discovery on outcome-free auxiliary + K-fold cross-fitted effect learning.
    log_path = output / 'stage2.structure.json' if rscript is None else output / 'stage2.R.log'
    stage2 = discover_and_fit_stage2(
        aux_x,
        dict(x=src_x, a=src_arms, y=src_y),
        dict(x=tgt_x, a=tgt_arms, y=tgt_y),
        plan,
        context_names=context_names,
        attribute_names=TSG_BINARY_ATTRIBUTE_NAMES,
        ci_seed=plan['ci_seed'],
        fit_seed=plan['fit_seed'],
        shuffle_seed=plan['shuffle_seed'],
        rscript=rscript,
        log_path=log_path,
    )
    write_bundle(
        output / 'stage2',
        {
            'result.json': dict(
                data=dict(
                    auxiliary=dict(x=aux_x),
                    source=dict(x=src_x, a=src_arms, y=src_y),
                    target=dict(x=tgt_x, a=tgt_arms, y=tgt_y),
                ),
                **stage2,
            )
        },
    )

    paired = [(arm, tgt_outcomes_map[f'tgt_{u["task_unit_id"]}']) for arm, u in zip(tgt_arms, target_units)]
    endpoints = dict(
        arm_0=_arm_endpoint_summary([pair for pair in paired if pair[0] == 0]),
        arm_1=_arm_endpoint_summary([pair for pair in paired if pair[0] == 1]),
        overall=_arm_endpoint_summary(paired),
    )
    func_delta = endpoints['arm_1']['functional_pass_rate'] - endpoints['arm_0']['functional_pass_rate']
    t_crit = float(t.ppf(1.0 - plan['component_alpha'] / 2.0, n_target - 1))
    margin = float(plan['practical_margin'])

    effect_estimates = {}
    for method, cf in stage2['cross_fit'].items():
        est, se = float(cf['effect']), float(cf['standard_error'])
        low, high = est - t_crit * se, est + t_crit * se
        effect_estimates[method] = dict(
            effect=est,
            standard_error=se,
            interval=[low, high],
            t_critical=t_crit,
            fallback_folds=int(cf['fallback_folds']),
            guidance_status=classify_scoped_guidance(low, high, margin, func_delta),
        )

    jci_res = effect_estimates['jci']
    jci_var_ratio = None
    if effect_estimates['target_only']['standard_error'] > 0:
        jci_var_ratio = float(
            1.0 - (jci_res['standard_error'] ** 2) / (effect_estimates['target_only']['standard_error'] ** 2)
        )

    summary = dict(
        study_id=plan['study_id'],
        study_mode='natural_task',
        evidence_role=plan['evidence_role'],
        assigned_n=n_target,
        target_folds=plan['target_folds'],
        reliability_gate_passed=bool(reliability['gate_passed']),
        median_attribute_flip_rate=float(reliability['median_flip_rate']),
        direction_eligible=bool(stage2['direction_checks']['eligible']),
        selected_jci_profile=stage2['source']['models']['jci']['selected_profile'],
        jci_roles=stage2['roles'],
        endpoints=endpoints,
        functionality_itt_delta=func_delta,
        effect_estimates=effect_estimates,
        jci_effect=jci_res['effect'],
        jci_standard_error=jci_res['standard_error'],
        jci_interval=jci_res['interval'],
        jci_guidance_status=jci_res['guidance_status'],
        jci_se_variance_reduction_vs_target_only=jci_var_ratio,
        formal_claim_allowed=False,
        new_provider_calls=0,
    )
    write_bundle(output / 'summary', {'result.json': summary})
    return summary
