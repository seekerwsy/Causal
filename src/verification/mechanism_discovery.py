"""Independent verifier for Stage II JCI mechanism discovery and paired evaluations."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
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
from prompt_mechanism_study.records import content_hash


def _replay_sigmoid(x: np.ndarray | float) -> np.ndarray | float:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -30.0, 30.0)))


def _assert_close(actual: float, expected: float, label: str, *, tol: float = 1e-10) -> None:
    if not math.isfinite(actual) or abs(actual - expected) > tol:
        raise ValueError(f"Numerical mismatch in {label}: saved={actual!r}, replayed={expected!r}")


def _replay_binary_assoc(x: np.ndarray, y: np.ndarray) -> tuple[float, float]:
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


def _replay_scenario_params(scenario: str) -> tuple[float, float, float, float, float]:
    table = {
        "confounded_and_scoped": (0.60, 2.0, 3.2, 2.2, 2.8),
        "pure_latent_trap": (0.50, 0.8, 3.6, 2.3, 2.4),
        "multi_op_high_interference": (0.85, 1.8, 3.2, 2.2, 3.2),
        "null_spurious_only": (0.55, 1.7, 3.0, 0.0, 2.6),
    }
    if scenario not in table:
        raise ValueError(f"Unknown scenario: {scenario}")
    return table[scenario]


def _verify_cell_worker(args: tuple[str, int, int, Mapping[str, Any], Mapping[str, Any]]) -> dict[str, Any]:
    scenario, batch_seed, rep_index, plan, cell = args
    expected_id = f"{scenario}_s{batch_seed}_r{rep_index:02d}"
    if cell.get("cell_id") != expected_id:
        raise ValueError(f"Cell identity mismatch: {cell.get('cell_id')} != {expected_id}")

    p_shared, b_env, b_u, b_cau, b_bleed = _replay_scenario_params(scenario)
    disc_seed = int.from_bytes(
        bytes.fromhex(content_hash({"batch_seed": batch_seed, "scenario": scenario, "rep": rep_index, "split": "disc"}))[:8],
        "big",
    )
    eval_seed = int.from_bytes(
        bytes.fromhex(content_hash({"batch_seed": batch_seed, "scenario": scenario, "rep": rep_index, "split": "eval"}))[:8],
        "big",
    )
    ci_seed = int.from_bytes(
        bytes.fromhex(content_hash({"batch_seed": batch_seed, "scenario": scenario, "rep": rep_index, "role": "ci"}))[:8],
        "big",
    )
    rng_disc = np.random.default_rng(disc_seed)
    rng_eval = np.random.default_rng(eval_seed)

    n_disc = int(plan["n_discovery"])
    c_env = rng_disc.binomial(1, 0.50, size=n_disc)
    i_lat = rng_disc.binomial(1, 0.25, size=n_disc)
    i_cau = rng_disc.binomial(1, 0.25, size=n_disc)
    i_flat = rng_disc.binomial(1, 0.25, size=n_disc)
    u_lat = rng_disc.binomial(1, 0.50, size=n_disc)

    z_shared = rng_disc.binomial(1, p_shared, size=n_disc)
    z_env = rng_disc.binomial(1, _replay_sigmoid(-1.8 + 3.6 * c_env))
    z_lat = rng_disc.binomial(1, _replay_sigmoid(-2.0 + 3.8 * u_lat + 3.4 * i_lat))
    z_cau = rng_disc.binomial(1, _replay_sigmoid(-1.4 - 0.6 * c_env + 3.4 * i_cau))
    z_bleed = rng_disc.binomial(1, _replay_sigmoid(-2.8 + 3.6 * (i_flat * z_shared) + 0.5 * i_flat))
    y_sec = rng_disc.binomial(1, _replay_sigmoid(-2.4 + b_env * c_env + b_u * u_lat + b_cau * z_cau))
    y_func = rng_disc.binomial(1, _replay_sigmoid(2.0 - b_bleed * z_bleed))

    labels = [
        "C_env",
        "I_lat",
        "I_cau",
        "I_flat",
        "Z_shared",
        "Z_env",
        "Z_lat",
        "Z_cau",
        "Z_bleed",
        "Y_sec",
        "Y_func",
    ]
    data = np.column_stack([c_env, i_lat, i_cau, i_flat, z_shared, z_env, z_lat, z_cau, z_bleed, y_sec, y_func])
    context_vars = ["C_env", "I_lat", "I_cau", "I_flat"]
    sink_vars = ["Y_sec", "Y_func"]

    ci = ConditionalPermutation(data, labels, draws=int(plan["ci_draws"]), seed=ci_seed)
    pag_replay = discover_jci_pag(
        labels,
        ci,
        float(plan["ci_alpha"]),
        context_vars=context_vars,
        sink_vars=sink_vars,
        max_order=int(plan["maximum_skeleton_conditioning_order"]),
        majority_rule=True,
        on_insufficient_ci="conservative",
    )
    if len(ci.cache) != int(cell["n_ci_queries"]):
        raise ValueError(f"CI query count mismatch in {expected_id}")
    if pag_replay["pag"] != cell["pag"]["pag"] or pag_replay["ancestry"] != cell["pag"]["ancestry"]:
        raise ValueError(f"PAG mismatch in {expected_id}")

    idx = {name: i for i, name in enumerate(labels)}
    arr = np.asarray(pag_replay["pag"], dtype=int)
    directed = nx.DiGraph()
    directed.add_nodes_from(range(len(labels)))
    directed.add_edges_from((int(u), int(v)) for u, v in np.argwhere((arr == 2) & (arr.T == 3)))
    root_idxs = {idx[c] for c in context_vars}
    sink_idxs = {idx[s] for s in sink_vars}
    valid_pag = (
        pag_replay["status"] == "evaluated"
        and nx.is_directed_acyclic_graph(directed)
        and not any(arr[u, r] == 2 for r in root_idxs for u in range(len(labels)) if u != r)
        and not any(arr[u, s] == 3 for s in sink_idxs for u in range(len(labels)) if u not in sink_idxs)
    )
    if bool(valid_pag) != bool(cell["discovery"]["pag_valid"]):
        raise ValueError(f"PAG validity mismatch in {expected_id}")

    probe_vars = ("I_cau", "I_flat", "I_lat")
    probe_map = {"Z_lat": "I_lat", "Z_cau": "I_cau"}
    obs_mask = np.all(data[:, [idx[p] for p in probe_vars]] == 0, axis=1)
    obs_data = data[obs_mask] if np.count_nonzero(obs_mask) >= 4 else data
    y_sec_obs = obs_data[:, idx["Y_sec"]]
    y_sec_all = data[:, idx["Y_sec"]]

    alpha = float(plan["ci_alpha"])
    replayed_roles: dict[str, str] = {}
    replayed_stats: dict[str, dict[str, float]] = {}
    for mech in ("Z_env", "Z_lat", "Z_cau"):
        m_i = idx[mech]
        obs_d, obs_p = _replay_binary_assoc(obs_data[:, m_i], y_sec_obs)
        probe = probe_map.get(mech)
        if probe is not None:
            others = [idx[p] for p in probe_vars if p != probe]
            clean = np.all(data[:, others] == 0, axis=1)
            sub_p = data[clean, idx[probe]]
            sub_y = y_sec_all[clean]
            if np.count_nonzero(sub_p == 1) >= 2 and np.count_nonzero(sub_p == 0) >= 2:
                pr_d, pr_p = _replay_binary_assoc(sub_p, sub_y)
            else:
                pr_d, pr_p = _replay_binary_assoc(data[:, idx[probe]], y_sec_all)
        else:
            pr_d, pr_p = obs_d, obs_p

        y_i = idx["Y_sec"]
        adj_s = valid_pag and arr[m_i, y_i] != 0
        dir_s = valid_pag and nx.has_path(directed, m_i, y_i)
        bi_s = adj_s and arr[m_i, y_i] == 2 and arr[y_i, m_i] == 2
        circ_s = adj_s and arr[m_i, y_i] == 2 and arr[y_i, m_i] == 1
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
        replayed_stats[mech] = {"obs_delta": obs_d, "obs_p": obs_p, "probe_delta": pr_d, "probe_p": pr_p}

    if replayed_roles != cell["discovery"]["classifications"]:
        raise ValueError(f"Classification mismatch in {expected_id}")

    causal_selected = sorted(
        (m for m, r in replayed_roles.items() if r == "causal_security_driver"),
        key=lambda m: (-replayed_stats[m]["probe_delta"], replayed_stats[m]["probe_p"], m),
    )
    corr_budget = max(1, len(causal_selected))
    corr_selected = sorted(
        (
            m for m in ("Z_env", "Z_lat", "Z_cau")
            if replayed_stats[m]["obs_delta"] > 0.0
            and (replayed_stats[m]["obs_delta"] >= 0.08 or replayed_stats[m]["obs_p"] <= alpha)
        ),
        key=lambda m: (-replayed_stats[m]["obs_delta"], replayed_stats[m]["obs_p"], m),
    )[:corr_budget]

    if causal_selected != cell["discovery"]["jci_policy"]["selected_mechanisms"]:
        raise ValueError(f"JCI policy selection mismatch in {expected_id}")
    if corr_selected != cell["discovery"]["corr_policy"]["selected_mechanisms"]:
        raise ValueError(f"Corr policy selection mismatch in {expected_id}")

    hazards = []
    for var_name in ("I_flat", "Z_bleed"):
        v_i = idx[var_name]
        fd, fp = _replay_binary_assoc(data[:, v_i], data[:, idx["Y_func"]])
        hp = valid_pag and nx.has_path(directed, v_i, idx["Y_func"])
        if (hp and fd < 0.0) or (fd <= -0.08 and fp <= alpha):
            hazards.append(var_name)
    if bool(hazards) != bool(cell["discovery"]["scope_bleed_detected"]):
        raise ValueError(f"Scope bleed flag mismatch in {expected_id}")

    # Replay held-out counterfactual evaluation
    n_eval = int(plan["n_eval"])
    c_e = rng_eval.binomial(1, 0.50, size=n_eval)
    u_e = rng_eval.binomial(1, 0.50, size=n_eval)
    z_sh_e = rng_eval.binomial(1, p_shared, size=n_eval)
    noise_lat = rng_eval.random(size=n_eval)
    noise_cau = rng_eval.random(size=n_eval)
    noise_bleed = rng_eval.random(size=n_eval)
    noise_sec = rng_eval.random(size=n_eval)
    noise_func = rng_eval.random(size=n_eval)

    def _sim_arm(selected: Sequence[str], mode: str) -> dict[str, np.ndarray]:
        act_l = 1 if "Z_lat" in selected else 0
        act_c = 1 if "Z_cau" in selected else 0
        act_f = 1 if (mode == "flat" and len(selected) > 0) else 0
        zc = (noise_cau < _replay_sigmoid(-1.4 - 0.6 * c_e + 3.4 * act_c)).astype(int)
        _ = (noise_lat < _replay_sigmoid(-2.0 + 3.8 * u_e + 3.4 * act_l)).astype(int)
        zb = (noise_bleed < _replay_sigmoid(-2.8 + 3.6 * (act_f * z_sh_e) + 0.5 * act_f)).astype(int)
        sec = (noise_sec < _replay_sigmoid(-2.4 + b_env * c_e + b_u * u_e + b_cau * zc)).astype(int)
        fnc = (noise_func < _replay_sigmoid(2.0 - b_bleed * zb)).astype(int)
        jnt = ((sec == 1) & (fnc == 1)).astype(float)
        return {"secure_yield": sec.astype(float), "functionality": fnc.astype(float), "joint": jnt}

    arm_vecs = {
        "baseline": _sim_arm([], "baseline"),
        "corr_tsg": _sim_arm(corr_selected, "tsg_scoped"),
        "jci_flat": _sim_arm(causal_selected, "flat"),
        "jci_tsg": _sim_arm(causal_selected, "tsg_scoped"),
    }
    saved_rates = cell["paired"]["arm_rates"]
    for arm, vecs in arm_vecs.items():
        _assert_close(saved_rates[arm]["secure_yield_rate"], float(np.mean(vecs["secure_yield"])), f"{expected_id}.{arm}.sec")
        _assert_close(saved_rates[arm]["functional_pass_rate"], float(np.mean(vecs["functionality"])), f"{expected_id}.{arm}.func")
        _assert_close(saved_rates[arm]["joint_success_rate"], float(np.mean(vecs["joint"])), f"{expected_id}.{arm}.joint")

    eval_alpha = float(plan["eval_alpha"])
    margin = float(plan["practical_margin"])
    n_primary = int(cell["paired"]["n_primary_comparisons"])
    if n_primary != 3:
        raise ValueError(f"Expected 3 primary comparisons, got {n_primary}")
    t_nom = float(t.ppf(1.0 - eval_alpha / 2.0, df=n_eval - 1))
    t_bonf = float(t.ppf(1.0 - eval_alpha / (2.0 * n_primary), df=n_eval - 1))

    for comp in cell["paired"]["comparisons"]:
        ya = arm_vecs[comp["arm_a"]][comp["endpoint"]]
        yb = arm_vecs[comp["arm_b"]][comp["endpoint"]]
        diff = ya - yb
        est = float(np.mean(diff))
        sd = float(np.std(diff, ddof=1))
        se = sd / math.sqrt(n_eval)
        ci_l = est - t_nom * se
        ci_h = est + t_nom * se
        b_l = est - t_bonf * se
        b_h = est + t_bonf * se
        nw = int(np.count_nonzero(diff > 0.0))
        nl = int(np.count_nonzero(diff < 0.0))
        nt = int(np.count_nonzero(diff == 0.0))
        sp = float(binomtest(nw, nw + nl, 0.5).pvalue) if (nw + nl) > 0 else 1.0
        unp_se = math.sqrt((float(np.var(ya, ddof=1)) + float(np.var(yb, ddof=1))) / n_eval)
        pvr = 1.0 - (se * se) / (unp_se * unp_se) if unp_se > 1e-12 else 0.0

        _assert_close(comp["estimate"], est, f"{expected_id}.{comp['id']}.est")
        _assert_close(comp["se"], se, f"{expected_id}.{comp['id']}.se")
        _assert_close(comp["ci_low"], ci_l, f"{expected_id}.{comp['id']}.ci_low")
        _assert_close(comp["ci_high"], ci_h, f"{expected_id}.{comp['id']}.ci_high")
        _assert_close(comp["bonferroni_low"], b_l, f"{expected_id}.{comp['id']}.bonf_low")
        _assert_close(comp["bonferroni_high"], b_h, f"{expected_id}.{comp['id']}.bonf_high")
        _assert_close(comp["sign_test_p_value"], sp, f"{expected_id}.{comp['id']}.sign_p")
        _assert_close(comp["pairing_variance_reduction"], pvr, f"{expected_id}.{comp['id']}.vr")
        if (comp["n_win"], comp["n_loss"], comp["n_tie"]) != (nw, nl, nt):
            raise ValueError(f"Win/loss/tie mismatch in {expected_id}.{comp['id']}")
        if bool(comp["practically_positive"]) != bool(b_l > 0.0 and est >= margin):
            raise ValueError(f"practically_positive mismatch in {expected_id}.{comp['id']}")

    true_drivers = set() if scenario == "null_spurious_only" else {"Z_cau"}
    if int(cell["false_positive_jci"]) != len(set(causal_selected) - true_drivers):
        raise ValueError(f"false_positive_jci mismatch in {expected_id}")
    if int(cell["false_positive_corr"]) != len(set(corr_selected) - true_drivers):
        raise ValueError(f"false_positive_corr mismatch in {expected_id}")

    return {"cell_id": expected_id, "n_ci_queries": len(ci.cache)}


def verify_mechanism_study(output_dir: Path, *, workers: int = 1) -> dict[str, Any]:
    """Independently replay all RNG streams, PAGs, mechanism classifications, paired CIs, and summary verdicts."""
    if type(workers) is not int or workers < 1:
        raise ValueError("workers must be a positive integer")
    out_dir = Path(output_dir).resolve()
    verify_bundle(out_dir / "inputs")
    verify_bundle(out_dir / "cells")
    verify_bundle(out_dir / "summary")

    plan = read_json(out_dir / "inputs" / "plan.json")
    summary = read_json(out_dir / "summary" / "result.json")
    manifest = read_json(out_dir / "manifest.json")

    if plan.get("study_mode") != "mechanism_simulation" or plan.get("formal_claim_allowed") is not False:
        raise ValueError("Invalid saved study contract")
    if file_sha256(out_dir / "source.zip") != manifest["source_zip_sha256"]:
        raise ValueError("source.zip digest mismatch")
    if content_hash(plan) != manifest["plan_sha256"]:
        raise ValueError("plan digest mismatch")
    if content_hash(summary) != manifest["summary_sha256"]:
        raise ValueError("summary digest mismatch")

    jobs = [
        (scenario, seed, rep)
        for scenario in plan["scenarios"]
        for seed in plan["batch_seeds"]
        for rep in range(int(plan.get("repetitions_per_seed", 1)))
    ]
    if len(jobs) != int(manifest["n_cells"]) or len(jobs) != int(summary["n_cells"]):
        raise ValueError("Saved cell count does not match plan")

    cells: list[dict[str, Any]] = []
    worker_args = []
    for scenario, seed, rep in jobs:
        cell_id = f"{scenario}_s{seed}_r{rep:02d}"
        cell_path = out_dir / "cells" / f"{cell_id}.json"
        if not cell_path.is_file():
            raise ValueError(f"Missing cell file: {cell_path}")
        cell = read_json(cell_path)
        if content_hash(cell) != manifest["cell_digests"].get(cell_id):
            raise ValueError(f"Cell digest mismatch for {cell_id}")
        cells.append(cell)
        worker_args.append((scenario, seed, rep, plan, cell))

    if workers == 1:
        replayed = [_verify_cell_worker(item) for item in worker_args]
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            replayed = list(pool.map(_verify_cell_worker, worker_args))

    total_queries = sum(int(item["n_ci_queries"]) for item in replayed)
    if total_queries != int(summary["total_ci_queries"]):
        raise ValueError("total_ci_queries mismatch in summary")

    by_scenario: dict[str, list[Mapping[str, Any]]] = {}
    for cell in cells:
        by_scenario.setdefault(str(cell["scenario"]), []).append(cell)
    if set(by_scenario) != set(summary["scenario_summaries"]):
        raise ValueError("Scenario keys mismatch in summary")

    for scenario, rows in by_scenario.items():
        saved_sc = summary["scenario_summaries"][scenario]
        if int(saved_sc["n_cells"]) != len(rows):
            raise ValueError(f"n_cells mismatch for {scenario}")
        if int(saved_sc["jci_false_discovery_cells"]) != sum(1 for r in rows if r["false_positive_jci"] > 0):
            raise ValueError(f"jci_false_discovery_cells mismatch for {scenario}")
        if int(saved_sc["corr_false_discovery_cells"]) != sum(1 for r in rows if r["false_positive_corr"] > 0):
            raise ValueError(f"corr_false_discovery_cells mismatch for {scenario}")
        _assert_close(
            saved_sc["jci_abstention_rate"],
            float(np.mean([1.0 if r["discovery"]["jci_policy"]["abstained"] else 0.0 for r in rows])),
            f"{scenario}.abstention",
        )
        for cid, saved_comp in saved_sc["comparisons"].items():
            matched = [next(c for c in r["paired"]["comparisons"] if c["id"] == cid) for r in rows]
            _assert_close(saved_comp["mean_estimate"], float(np.mean([m["estimate"] for m in matched])), f"{scenario}.{cid}.mean")
            if int(saved_comp["significant_positive_cells"]) != sum(1 for m in matched if m["significant_positive"]):
                raise ValueError(f"significant_positive_cells mismatch in {scenario}.{cid}")

    null_sc = summary["scenario_summaries"].get("null_spurious_only")
    null_clean = True if null_sc is None else (int(null_sc["jci_false_discovery_cells"]) == 0)
    active = [s for s in summary["scenario_summaries"] if s != "null_spurious_only"]
    jci_beats_corr = all(
        summary["scenario_summaries"][s]["comparisons"]["jci_tsg_vs_corr_tsg"]["mean_estimate"] > 0.0
        for s in active
    )
    tsg_beats_flat = all(
        summary["scenario_summaries"][s]["comparisons"]["jci_tsg_vs_jci_flat"]["mean_estimate"] > 0.0
        for s in active
    )
    expected_verdict = {
        "null_control_abstention_passed": bool(null_clean),
        "jci_outperforms_corr_on_joint": bool(jci_beats_corr),
        "tsg_outperforms_flat_on_joint": bool(tsg_beats_flat),
        "overall_passed": bool(null_clean and jci_beats_corr and tsg_beats_flat),
    }
    if expected_verdict != summary["verdict"]:
        raise ValueError(f"Summary verdict mismatch: saved={summary['verdict']}, expected={expected_verdict}")

    return {
        "status": "VERIFIED",
        "study_id": plan["study_id"],
        "n_cells_verified": len(cells),
        "total_ci_queries": total_queries,
        "summary_sha256": manifest["summary_sha256"],
        "verdict": expected_verdict,
    }
