"""Independent end-to-end verifier for natural-task Stage I -> Stage II -> paired evaluation."""

from __future__ import annotations

import math
from pathlib import Path
from typing import Any, Mapping, Sequence

import networkx as nx
import numpy as np
from scipy.stats import binomtest, fisher_exact, t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, verify_bundle
from prompt_mechanism_study.discovery.jci_structure import (
    ConditionalPermutation,
    discover_jci_pag,
)
from prompt_mechanism_study.experiment.code_generation import splice_target_unit_code
from prompt_mechanism_study.experiment.outcomes import derive_outcomes
from prompt_mechanism_study.measurement.evaluate import (
    CodeStatus,
    FunctionalStatus,
    Measurement,
    MeasurementLedger,
    OracleStatus,
)
from prompt_mechanism_study.measurement.security_profiles import (
    LOCAL_PROFILE_IDS,
    evaluate_security_profile,
)
from prompt_mechanism_study.measurement.unit_test_oracle import evaluate_python_unit_tests
from prompt_mechanism_study.records import canonical_value, content_hash
from prompt_mechanism_study.tsg.prompt_contract import compile_source_propositions
from prompt_mechanism_study.tsg.scoped_intervention import render_prompt_intervention
from prompt_mechanism_study.tsg.source_representation import (
    TSG_ORTHOGONAL_MECHANISM_NAMES,
    evaluate_binary_attribute_reliability,
    extract_tsg_structural_attributes,
)


ARMS = ("baseline", "corr_tsg", "jci_flat", "jci_tsg")


def _assert_close(actual: float, expected: float, label: str, *, tol: float = 1e-10) -> None:
    if not math.isfinite(actual) or abs(actual - expected) > tol:
        raise ValueError(f"Numerical mismatch in {label}: saved={actual!r}, replayed={expected!r}")


def _binary_assoc(x: np.ndarray, y: np.ndarray) -> tuple[float, float]:
    m1 = x == 1
    m0 = x == 0
    n1 = int(np.count_nonzero(m1))
    n0 = int(np.count_nonzero(m0))
    if n1 == 0 or n0 == 0:
        return 0.0, 1.0
    p1 = float(np.mean(y[m1]))
    p0 = float(np.mean(y[m0]))
    a = int(np.count_nonzero(y[m1] == 1))
    b = n1 - a
    c = int(np.count_nonzero(y[m0] == 1))
    d = n0 - c
    _, p_val = fisher_exact([[a, b], [c, d]], alternative="two-sided")
    return p1 - p0, float(p_val)


def verify_natural_study(output_dir: Path) -> dict[str, Any]:
    """Independently replay all Stage I TSGs, Stage II JCI discovery, measurements, and paired CIs."""
    out_dir = Path(output_dir).resolve()
    for subdir in ("inputs", "stage1", "stage2", "measurements", "outcomes", "summary"):
        verify_bundle(out_dir / subdir)

    plan = read_json(out_dir / "inputs" / "plan.json")
    benchmark = read_json(out_dir / "inputs" / "benchmark.json")
    stage1_eval = read_json(out_dir / "stage1" / "evaluation_attributes.json")["rows"]
    reliability_saved = read_json(out_dir / "stage1" / "reliability.json")
    pag_saved = read_json(out_dir / "stage2" / "pag.json")
    discovery_saved = read_json(out_dir / "stage2" / "discovery.json")
    ledger_saved = read_json(out_dir / "measurements" / "ledger.json")
    detail_rows = read_json(out_dir / "measurements" / "details.json")["rows"]
    outcomes_saved = read_json(out_dir / "outcomes" / "records.json")["rows"]
    paired_saved = read_json(out_dir / "outcomes" / "paired.json")
    summary = read_json(out_dir / "summary" / "result.json")
    manifest = read_json(out_dir / "manifest.json")

    if plan.get("study_mode") != "natural_task" or plan.get("formal_claim_allowed") is not False:
        raise ValueError("Invalid saved natural study plan")
    if summary.get("formal_claim_allowed") is not False:
        raise ValueError("Saved natural study summary violated formal_claim_allowed=false")
    if file_sha256(out_dir / "source.zip") != manifest["source_zip_sha256"]:
        raise ValueError("source.zip digest mismatch")
    if content_hash(plan) != manifest["plan_sha256"]:
        raise ValueError("plan.json digest mismatch")
    if content_hash(benchmark) != manifest["benchmark_sha256"]:
        raise ValueError("benchmark.json digest mismatch")
    if content_hash(summary) != manifest["summary_sha256"]:
        raise ValueError("summary digest mismatch")

    disc = benchmark["discovery_cohort"]
    eval_tasks = list(benchmark["evaluation_cohort"])
    eval_ids = [t["task_unit_id"] for t in eval_tasks]
    if len(eval_ids) < 2 or len(eval_ids) != len(set(eval_ids)):
        raise ValueError("Evaluation cohort task_unit_ids must be deduplicated (>= 2)")
    if set(disc["task_unit_ids"]) & set(eval_ids):
        raise ValueError("Discovery and evaluation splits overlap")
    for task in eval_tasks:
        if task["oracle_profile_id"] not in LOCAL_PROFILE_IDS:
            raise ValueError(f"Unsupported profile in benchmark: {task['oracle_profile_id']}")

    # 1. Independently replay Stage I Prompt TSG and orthogonal mechanism vectors
    compiled_eval: dict[str, tuple[Any, dict[str, Any]]] = {}
    replayed_stage1: dict[str, dict[str, Any]] = {}
    for task in eval_tasks:
        tid = task["task_unit_id"]
        graph, compiled = compile_source_propositions(
            {"task_unit_id": tid, "prompt": task["prompt"]},
            task["record"],
            extractor_id="natural-stage1-eval",
            tolerant=True,
        )
        ids = compiled["local_node_ids"]
        tgt = task.get("target", {})
        op_id = ids.get(tgt.get("operation_local_id")) if tgt.get("operation_local_id") else None
        req_id = ids.get(tgt.get("requirement_local_id")) if tgt.get("requirement_local_id") else None
        attrs = extract_tsg_structural_attributes(
            graph,
            operation_node_id=op_id,
            requirement_node_id=req_id,
            prompt=task["prompt"],
            catalog=compiled["catalog"],
        )
        compiled_eval[tid] = (graph, compiled)
        replayed_stage1[tid] = {
            "task_unit_id": tid,
            "tsg_id": graph.tsg_id,
            "degraded_local_ids": compiled.get("degraded_local_ids", []),
            "orthogonal_mechanism_vector": attrs["orthogonal_mechanism_vector"],
            "local_binding_complete": bool(attrs["local_binding_complete"]),
            "local_unresolved_count": int(attrs["local_unresolved_count"]),
        }

    saved_stage1_map = {row["task_unit_id"]: row for row in stage1_eval}
    if saved_stage1_map != replayed_stage1:
        raise ValueError("Stage I Prompt TSG attributes mismatch")

    cal_rows = list(benchmark.get("calibration_records", []))
    if cal_rows:
        ref_vecs, cand_vecs = [], []
        for row in cal_rows:
            orig_id = row["task_unit_id"].removeprefix("cal_")
            c_graph, c_comp = compile_source_propositions(
                row["task"],
                row["record"],
                extractor_id="natural-stage1-calibration",
                tolerant=True,
            )
            c_ids = c_comp["local_node_ids"]
            c_tgt = row.get("target", {})
            c_attrs = extract_tsg_structural_attributes(
                c_graph,
                operation_node_id=c_ids.get(c_tgt.get("operation_local_id")) if c_tgt.get("operation_local_id") else None,
                requirement_node_id=c_ids.get(c_tgt.get("requirement_local_id")) if c_tgt.get("requirement_local_id") else None,
                prompt=row["task"]["prompt"],
                catalog=c_comp["catalog"],
            )
            cand_vecs.append(c_attrs["orthogonal_mechanism_vector"])
            ref_vecs.append(
                replayed_stage1[orig_id]["orthogonal_mechanism_vector"]
                if orig_id in replayed_stage1
                else c_attrs["orthogonal_mechanism_vector"]
            )
        replayed_rel = evaluate_binary_attribute_reliability(
            ref_vecs,
            cand_vecs,
            attribute_names=TSG_ORTHOGONAL_MECHANISM_NAMES,
            max_median_flip_rate=float(plan.get("max_median_flip_rate", 0.05)),
            max_attribute_flip_rate=float(plan.get("max_attribute_flip_rate", 0.10)),
        )
        if content_hash(replayed_rel) != content_hash(reliability_saved):
            raise ValueError("Stage I reliability report mismatch")

    # 2. Independently replay Stage II JCI PAG and mechanism classifications
    disc_data = np.asarray(disc["rows"], dtype=int)
    labels = list(disc["labels"])
    ci = ConditionalPermutation(disc_data, labels, draws=int(plan["ci_draws"]), seed=int(plan["ci_seed"]))
    pag_replay = discover_jci_pag(
        labels,
        ci,
        float(plan["ci_alpha"]),
        context_vars=disc["context_vars"],
        sink_vars=disc["sink_vars"],
        max_order=int(plan["maximum_skeleton_conditioning_order"]),
        majority_rule=True,
        on_insufficient_ci="conservative",
    )
    if pag_replay["pag"] != pag_saved["pag"] or pag_replay["ancestry"] != pag_saved["ancestry"]:
        raise ValueError("Stage II PAG mismatch")

    idx = {name: i for i, name in enumerate(labels)}
    arr = np.asarray(pag_replay["pag"], dtype=int)
    directed = nx.DiGraph()
    directed.add_nodes_from(range(len(labels)))
    directed.add_edges_from((int(u), int(v)) for u, v in np.argwhere((arr == 2) & (arr.T == 3)))
    root_set = {idx[c] for c in disc["context_vars"]}
    sink_set = {idx[s] for s in disc["sink_vars"]}
    valid_pag = (
        pag_replay["status"] == "evaluated"
        and nx.is_directed_acyclic_graph(directed)
        and not any(arr[u, r] == 2 for r in root_set for u in range(len(labels)) if u != r)
        and not any(arr[u, s] == 3 for s in sink_set for u in range(len(labels)) if u not in sink_set)
    )
    if bool(valid_pag) != bool(discovery_saved["pag_valid"]):
        raise ValueError("Stage II PAG validity mismatch")

    probe_map = dict(disc["probe_map"])
    flat_probe_var = disc.get("flat_probe_var")
    bleed_vars = list(disc.get("bleed_vars", ()))
    probe_vars = sorted(
        set(probe_map.values()) | ({flat_probe_var} if flat_probe_var and flat_probe_var in idx else set())
    )
    obs_mask = np.all(disc_data[:, [idx[p] for p in probe_vars]] == 0, axis=1) if probe_vars else np.ones(len(disc_data), dtype=bool)
    obs_data = disc_data[obs_mask] if np.count_nonzero(obs_mask) >= 4 else disc_data
    sec_sink = disc["sink_vars"][0]
    func_sink = disc["sink_vars"][1]
    idx_ys = idx[sec_sink]
    idx_yf = idx[func_sink]
    alpha = float(plan["ci_alpha"])

    replayed_roles: dict[str, str] = {}
    replayed_mstats: dict[str, dict[str, float]] = {}
    for mech in disc["mechanism_vars"]:
        m_i = idx[mech]
        obs_d, obs_p = _binary_assoc(obs_data[:, m_i], obs_data[:, idx_ys])
        probe = probe_map.get(mech)
        if probe is not None:
            others = [idx[p] for p in probe_vars if p != probe]
            if others:
                clean = np.all(disc_data[:, others] == 0, axis=1)
                sub_p = disc_data[clean, idx[probe]]
                sub_y = disc_data[clean, idx_ys]
                pr_d, pr_p = (
                    _binary_assoc(sub_p, sub_y)
                    if np.count_nonzero(sub_p == 1) >= 2 and np.count_nonzero(sub_p == 0) >= 2
                    else _binary_assoc(disc_data[:, idx[probe]], disc_data[:, idx_ys])
                )
            else:
                pr_d, pr_p = _binary_assoc(disc_data[:, idx[probe]], disc_data[:, idx_ys])
        else:
            pr_d, pr_p = obs_d, obs_p

        adj_s = valid_pag and arr[m_i, idx_ys] != 0
        dir_s = valid_pag and nx.has_path(directed, m_i, idx_ys)
        bi_s = adj_s and arr[m_i, idx_ys] == 2 and arr[idx_ys, m_i] == 2
        circ_s = adj_s and arr[m_i, idx_ys] == 2 and arr[idx_ys, m_i] == 1
        eff = pr_d if probe is not None else obs_d
        if dir_s and eff > 0.0:
            role = "causal_security_driver"
        elif bi_s:
            role = "latent_confounded_proxy"
        elif circ_s:
            role = "unconfirmed_ambiguous"
        elif abs(obs_d) >= 0.08 or obs_p <= alpha:
            role = "environment_confounded_proxy"
        else:
            role = "inactive_or_null"
        replayed_roles[mech] = role
        replayed_mstats[mech] = {"obs_delta": obs_d, "obs_p": obs_p, "probe_delta": pr_d, "probe_p": pr_p}

    if replayed_roles != discovery_saved["classifications"]:
        raise ValueError("Stage II mechanism classifications mismatch")

    jci_selected = sorted(
        (m for m, r in replayed_roles.items() if r == "causal_security_driver"),
        key=lambda m: (-replayed_mstats[m]["probe_delta"], replayed_mstats[m]["probe_p"], m),
    )
    corr_budget = max(1, len(jci_selected))
    corr_selected = sorted(
        (
            m for m in disc["mechanism_vars"]
            if replayed_mstats[m]["obs_delta"] > 0.0
            and (replayed_mstats[m]["obs_delta"] >= 0.08 or replayed_mstats[m]["obs_p"] <= alpha)
        ),
        key=lambda m: (-replayed_mstats[m]["obs_delta"], replayed_mstats[m]["obs_p"], m),
    )[:corr_budget]

    if jci_selected != discovery_saved["jci_policy"]["selected_mechanisms"]:
        raise ValueError("JCI selected mechanisms mismatch")
    if corr_selected != discovery_saved["corr_policy"]["selected_mechanisms"]:
        raise ValueError("Correlation selected mechanisms mismatch")

    hazards = []
    seen_cands: set[str] = set()
    for v_name in ([flat_probe_var] if flat_probe_var else []) + bleed_vars:
        if not v_name or v_name not in idx or v_name in seen_cands:
            continue
        seen_cands.add(v_name)
        fd, fp = _binary_assoc(disc_data[:, idx[v_name]], disc_data[:, idx_yf])
        hp = valid_pag and nx.has_path(directed, idx[v_name], idx_yf)
        if (hp and fd < 0.0) or (fd <= -0.08 and fp <= alpha):
            hazards.append(v_name)
    if bool(hazards) != bool(discovery_saved["scope_bleed_detected"]):
        raise ValueError("Scope bleed flag mismatch")

    # 3. Independently replay prompts, AST splicing, security Oracle, unit tests, and outcomes
    detail_by_id = {row["assignment_id"]: row for row in detail_rows}
    if len(detail_rows) != len(eval_tasks) * len(ARMS):
        raise ValueError("Expected full 4-arm paired ITT denominator in measurements")
    unit_timeout = float(plan.get("unit_test_timeout_seconds", 5.0))
    provider_mode = plan.get("provider_mode", "offline_fixture")
    replayed_measurements: list[Measurement] = []

    for task in eval_tasks:
        tid = task["task_unit_id"]
        graph, compiled = compiled_eval[tid]
        local_ids = compiled["local_node_ids"]
        mechs = task["mechanisms"]
        arm_specs = {
            "baseline": ("baseline", []),
            "corr_tsg": ("tsg_scoped", [mechs[mid] for mid in corr_selected if mid in mechs]),
            "jci_flat": ("flat", [mechs[mid] for mid in jci_selected if mid in mechs]),
            "jci_tsg": (
                discovery_saved["jci_policy"]["recommended_mode"] if jci_selected else "tsg_scoped",
                [mechs[mid] for mid in jci_selected if mid in mechs],
            ),
        }
        for arm in ARMS:
            aid = f"{tid}__{arm}"
            detail = detail_by_id.get(aid)
            if detail is None:
                raise ValueError(f"Missing measurement detail for {aid}")
            mode, sel_mechs = arm_specs[arm]
            rendered = render_prompt_intervention(
                task["prompt"],
                mode=mode,
                mechanisms=sel_mechs,
                graph=graph,
                local_node_ids=local_ids,
            )
            if rendered["rendered_prompt"] != detail["rendered_prompt"] or list(rendered["applied_mechanisms"]) != detail["applied_mechanisms"]:
                raise ValueError(f"Intervention rendering mismatch for {aid}")
            if provider_mode == "offline_fixture" and detail["raw_response"] != task["offline_responses"][arm]:
                raise ValueError(f"Offline response mismatch for {aid}")

            gen_digest = content_hash(detail["raw_response"])
            if detail.get("provider_error") is not None:
                if detail["code_status"] != CodeStatus.NO_CODE.value:
                    raise ValueError(f"Provider error arm must retain NO_CODE status: {aid}")
                replayed_measurements.append(
                    Measurement(
                        aid,
                        CodeStatus.NO_CODE,
                        OracleStatus.NOT_RUN,
                        FunctionalStatus.NOT_RUN,
                        gen_digest,
                        terminal_reason=detail["terminal_reason"],
                    )
                )
                continue

            splice = splice_target_unit_code(
                task.get("scaffold_code", ""),
                detail["raw_response"],
                target_symbol=task.get("target_symbol"),
            )
            if splice["code_status"] != detail["code_status"]:
                raise ValueError(f"Splice status mismatch for {aid}")
            if splice["code_status"] != "valid":
                replayed_measurements.append(
                    Measurement(
                        aid,
                        CodeStatus(splice["code_status"]),
                        OracleStatus.NOT_RUN,
                        FunctionalStatus.NOT_RUN,
                        gen_digest,
                        terminal_reason=str(splice["terminal_reason"] or splice["code_status"]),
                    )
                )
                continue

            spliced_code = str(splice["spliced_code"])
            if splice["code_sha256"] != detail["code_sha256"] or spliced_code != detail["spliced_code"]:
                raise ValueError(f"Spliced code digest mismatch for {aid}")
            sec = evaluate_security_profile(spliced_code, task["oracle_profile_id"])
            ut = evaluate_python_unit_tests(spliced_code, task["unit_test_script"], timeout_seconds=unit_timeout)
            if sec["security_label"] != detail["oracle_status"]:
                raise ValueError(f"Security Oracle replay mismatch for {aid}")
            if ut["functional_label"] != detail["functional_status"]:
                raise ValueError(f"Unit test replay mismatch for {aid}")
            replayed_measurements.append(
                Measurement(
                    aid,
                    CodeStatus.VALID,
                    OracleStatus(sec["security_label"]),
                    FunctionalStatus(ut["functional_label"]),
                    gen_digest,
                    code_sha256=str(splice["code_sha256"]),
                    oracle_evidence_sha256=str(sec["mechanism_trace_sha256"]),
                    functional_evidence_sha256=str(ut["evidence_sha256"]),
                )
            )

    replayed_ledger = MeasurementLedger(
        study_id=plan["study_id"],
        randomization_id=ledger_saved["randomization_id"],
        adapter_bundle_id=ledger_saved["adapter_bundle_id"],
        measurements=tuple(replayed_measurements),
    )
    if content_hash(canonical_value(replayed_ledger)) != content_hash(ledger_saved):
        raise ValueError("MeasurementLedger replay mismatch")

    replayed_outcomes = derive_outcomes(replayed_ledger)
    if content_hash([canonical_value(row) for row in replayed_outcomes]) != content_hash(outcomes_saved):
        raise ValueError("Derived Outcome records replay mismatch")

    # 4. Independently replay 4-arm paired ITT statistics & summary metrics
    outcome_by_id = {row.assignment_id: row for row in replayed_outcomes}
    n = len(eval_tasks)
    vecs: dict[str, dict[str, np.ndarray]] = {}
    for arm in ARMS:
        rows = [outcome_by_id[f"{t['task_unit_id']}__{arm}"] for t in eval_tasks]
        cv = np.array([r.code_valid for r in rows], dtype=float)
        oe = np.array([r.oracle_evaluable for r in rows], dtype=float)
        us = np.array([int(r.code_valid == 1 and r.oracle_evaluable == 0) for r in rows], dtype=float)
        sy = np.array([r.secure_yield for r in rows], dtype=float)
        fp = np.array([1.0 if r.functionality == 1 else 0.0 for r in rows], dtype=float)
        jn = np.array([1.0 if (r.secure_yield == 1 and r.functionality == 1) else 0.0 for r in rows], dtype=float)
        vecs[arm] = {"code_valid": cv, "oracle_evaluable": oe, "unknown_security": us, "secure_yield": sy, "functionality": fp, "joint": jn}

        saved_rate = paired_saved["arm_rates"][arm]
        _assert_close(saved_rate["code_valid_rate"], float(np.mean(cv)), f"{arm}.code_valid_rate")
        _assert_close(saved_rate["oracle_evaluable_rate"], float(np.mean(oe)), f"{arm}.oracle_evaluable_rate")
        _assert_close(saved_rate["unknown_security_rate"], float(np.mean(us)), f"{arm}.unknown_security_rate")
        _assert_close(saved_rate["secure_yield_rate"], float(np.mean(sy)), f"{arm}.secure_yield_rate")
        _assert_close(saved_rate["functional_pass_rate"], float(np.mean(fp)), f"{arm}.functional_pass_rate")
        _assert_close(saved_rate["joint_success_rate"], float(np.mean(jn)), f"{arm}.joint_success_rate")
        if content_hash(saved_rate) != content_hash(summary["arm_rates"][arm]):
            raise ValueError(f"Summary arm_rates mismatch for {arm}")

    eval_alpha = float(plan["eval_alpha"])
    margin = float(plan["practical_margin"])
    n_primary = int(paired_saved["n_primary_comparisons"])
    t_nom = float(t.ppf(1.0 - eval_alpha / 2.0, df=n - 1))
    t_bonf = float(t.ppf(1.0 - eval_alpha / (2.0 * n_primary), df=n - 1))

    for comp, s_comp in zip(paired_saved["comparisons"], summary["comparisons"], strict=True):
        if content_hash(comp) != content_hash(s_comp):
            raise ValueError(f"Summary comparison mismatch for {comp['id']}")
        ya = vecs[comp["arm_a"]][comp["endpoint"]]
        yb = vecs[comp["arm_b"]][comp["endpoint"]]
        diff = ya - yb
        est = float(np.mean(diff))
        sd = float(np.std(diff, ddof=1))
        se = sd / math.sqrt(n)
        ci_l = est - t_nom * se
        ci_h = est + t_nom * se
        b_l = est - t_bonf * se
        b_h = est + t_bonf * se
        nw = int(np.count_nonzero(diff > 0.0))
        nl = int(np.count_nonzero(diff < 0.0))
        nt = int(np.count_nonzero(diff == 0.0))
        sp = float(binomtest(nw, nw + nl, 0.5).pvalue) if (nw + nl) > 0 else 1.0
        unp_se = math.sqrt((float(np.var(ya, ddof=1)) + float(np.var(yb, ddof=1))) / n)
        pvr = 1.0 - (se * se) / (unp_se * unp_se) if unp_se > 1e-12 else 0.0

        _assert_close(comp["estimate"], est, f"{comp['id']}.est")
        _assert_close(comp["se"], se, f"{comp['id']}.se")
        _assert_close(comp["ci_low"], ci_l, f"{comp['id']}.ci_low")
        _assert_close(comp["ci_high"], ci_h, f"{comp['id']}.ci_high")
        _assert_close(comp["bonferroni_low"], b_l, f"{comp['id']}.bonf_low")
        _assert_close(comp["bonferroni_high"], b_h, f"{comp['id']}.bonf_high")
        _assert_close(comp["sign_test_p_value"], sp, f"{comp['id']}.sign_p")
        _assert_close(comp["pairing_variance_reduction"], pvr, f"{comp['id']}.vr")
        if (comp["n_win"], comp["n_loss"], comp["n_tie"]) != (nw, nl, nt):
            raise ValueError(f"Win/loss/tie mismatch for {comp['id']}")
        if bool(comp["practically_positive"]) != bool(b_l > 0.0 and est >= margin):
            raise ValueError(f"practically_positive mismatch for {comp['id']}")

    return {
        "status": "VERIFIED",
        "study_id": plan["study_id"],
        "provider_mode": provider_mode,
        "n_eval_tasks": len(eval_tasks),
        "n_measurements_verified": len(replayed_measurements),
        "queries_verified": len(ci.cache),
        "summary_sha256": manifest["summary_sha256"],
    }
