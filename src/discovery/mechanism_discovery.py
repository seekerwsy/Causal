"""Joint Causal Inference mechanism discovery and paired counterfactual evaluation."""

from __future__ import annotations

from concurrent.futures import ProcessPoolExecutor
import math
import platform
from pathlib import Path
from typing import Any, Mapping, Sequence
import zipfile

import networkx as nx
import numpy as np
import scipy
from scipy.stats import binomtest, fisher_exact, t

from prompt_mechanism_study.artifact_io import file_sha256, read_json, write_bundle, write_json_new
from prompt_mechanism_study.discovery.jci_structure import (
    ConditionalPermutation,
    StructureBackend,
    discover_jci_pag,
)
from prompt_mechanism_study.records import content_hash


MECHANISM_SCENARIOS = (
    "confounded_and_scoped",
    "pure_latent_trap",
    "multi_op_high_interference",
    "null_spurious_only",
)

SOURCE_FILES = (
    "src/discovery/mechanism_discovery.py",
    "src/discovery/jci_structure.py",
    "src/discovery/jci_context.R",
    "src/verification/mechanism_discovery.py",
    "src/tsg/prompt_tsg.py",
    "src/tsg/prompt_contract.py",
    "src/tsg/source_representation.py",
    "src/tsg/scoped_intervention.py",
    "src/artifact_io.py",
    "src/records.py",
    "src/cli.py",
    "pyproject.toml",
)


def _sigmoid(x: np.ndarray | float) -> np.ndarray | float:
    return 1.0 / (1.0 + np.exp(-np.clip(x, -30.0, 30.0)))


def _binary_association(x: np.ndarray, y: np.ndarray) -> dict[str, float]:
    """Compute difference in means and exact two-sided Fisher p-value on 0/1 arrays."""
    mask1 = x == 1
    mask0 = x == 0
    n1 = int(np.count_nonzero(mask1))
    n0 = int(np.count_nonzero(mask0))
    if n1 == 0 or n0 == 0:
        return {"delta": 0.0, "p_value": 1.0, "n1": n1, "n0": n0}
    p1 = float(np.mean(y[mask1]))
    p0 = float(np.mean(y[mask0]))
    a = int(np.count_nonzero(y[mask1] == 1))
    b = n1 - a
    c = int(np.count_nonzero(y[mask0] == 1))
    d = n0 - c
    _, p_val = fisher_exact([[a, b], [c, d]], alternative="two-sided")
    return {"delta": p1 - p0, "p_value": float(p_val), "n1": n1, "n0": n0}


def validate_mechanism_plan(plan: Mapping[str, Any]) -> None:
    """Validate configuration invariants for a Stage II mechanism simulation study."""
    if plan.get("study_mode") != "mechanism_simulation":
        raise ValueError('Mechanism simulation requires study_mode == "mechanism_simulation"')
    if plan.get("formal_claim_allowed") is not False or plan.get("new_provider_calls", 0) != 0:
        raise ValueError("Mechanism simulation must keep formal_claim_allowed=false and new_provider_calls=0")
    scenarios = list(plan.get("scenarios", ()))
    if not scenarios or len(scenarios) != len(set(scenarios)) or set(scenarios) - set(MECHANISM_SCENARIOS):
        raise ValueError("Mechanism simulation requires unique declared scenarios from MECHANISM_SCENARIOS")
    seeds = list(plan.get("batch_seeds", ()))
    if not seeds or len(seeds) != len(set(seeds)) or any(type(s) is not int for s in seeds):
        raise ValueError("batch_seeds must be non-empty unique integers")
    for field in ("n_discovery", "n_eval", "ci_draws", "maximum_skeleton_conditioning_order"):
        val = plan.get(field)
        if type(val) is not int or val < 1:
            raise ValueError(f"{field} must be a positive integer")
    if plan["ci_draws"] < 99:
        raise ValueError("ci_draws must be >= 99")
    for field in ("ci_alpha", "eval_alpha", "practical_margin"):
        val = plan.get(field)
        if not isinstance(val, (int, float)) or not 0 < float(val) < 1:
            raise ValueError(f"{field} must lie strictly in (0, 1)")


def check_pag_direction_validity(
    pag: np.ndarray | Sequence[Sequence[int]],
    *,
    n_vars: int,
    root_indices: Sequence[int],
    sink_indices: Sequence[int],
) -> dict[str, Any]:
    """Verify DAG consistency of definite edges, exogenous roots, and post-generation sinks."""
    arr = np.asarray(pag, dtype=int)
    directed = nx.DiGraph()
    directed.add_nodes_from(range(n_vars))
    directed.add_edges_from((int(u), int(v)) for u, v in np.argwhere((arr == 2) & (arr.T == 3)))
    is_dag = bool(nx.is_directed_acyclic_graph(directed))
    root_set = set(root_indices)
    sink_set = set(sink_indices)
    no_arrows_into_context = not any(
        arr[u, r] == 2 for r in root_set for u in range(n_vars) if u != r
    )
    no_tails_out_of_sinks = not any(
        arr[u, s] == 3 for s in sink_set for u in range(n_vars) if u not in sink_set
    )
    valid = is_dag and no_arrows_into_context and no_tails_out_of_sinks
    return {
        "valid": bool(valid),
        "is_dag": is_dag,
        "no_arrows_into_context": no_arrows_into_context,
        "no_tails_out_of_sinks": no_tails_out_of_sinks,
        "directed_graph": directed,
    }


def classify_jci_mechanisms(
    pag_result: Mapping[str, Any],
    *,
    data: np.ndarray | Sequence[Sequence[int]],
    labels: Sequence[str],
    context_vars: Sequence[str],
    probe_map: Mapping[str, str],
    mechanism_vars: Sequence[str],
    security_sink: str = "Y_sec",
    functional_sink: str = "Y_func",
    flat_probe_var: str | None = None,
    bleed_vars: Sequence[str] = (),
    alpha: float = 0.05,
    min_corr: float = 0.08,
    max_mechanisms: int | None = None,
) -> dict[str, Any]:
    """Classify TSG mechanisms from a JCI PAG with post-generation sinks and derive policies."""
    arr_data = np.asarray(data, dtype=int)
    label_list = list(labels)
    idx = {name: i for i, name in enumerate(label_list)}
    for required in (*context_vars, *mechanism_vars, security_sink):
        if required not in idx:
            raise ValueError(f"Required variable {required!r} is missing from labels")
    for mech, probe in probe_map.items():
        if mech not in idx or probe not in idx:
            raise ValueError(f"Invalid probe mapping {(mech, probe)!r}")

    probe_vars = sorted(
        {probe for probe in probe_map.values()}
        | ({flat_probe_var} if flat_probe_var and flat_probe_var in idx else set())
    )
    if probe_vars:
        obs_mask = np.all(arr_data[:, [idx[p] for p in probe_vars]] == 0, axis=1)
        obs_data = arr_data[obs_mask] if np.count_nonzero(obs_mask) >= 4 else arr_data
    else:
        obs_data = arr_data

    y_sec_obs = obs_data[:, idx[security_sink]]
    y_sec_all = arr_data[:, idx[security_sink]]

    pag_ok = pag_result.get("status") == "evaluated" and pag_result.get("pag") is not None
    if pag_ok:
        pag_arr = np.asarray(pag_result["pag"], dtype=int)
        root_idxs = [idx[c] for c in context_vars]
        sink_idxs = [idx[s] for s in (security_sink, functional_sink) if s in idx]
        checks = check_pag_direction_validity(
            pag_arr,
            n_vars=len(label_list),
            root_indices=root_idxs,
            sink_indices=sink_idxs,
        )
        valid_pag = checks["valid"]
        directed = checks["directed_graph"]
    else:
        pag_arr = None
        checks = {
            "valid": False,
            "is_dag": False,
            "no_arrows_into_context": False,
            "no_tails_out_of_sinks": False,
        }
        valid_pag = False
        directed = nx.DiGraph()

    idx_y_sec = idx[security_sink]
    classifications: dict[str, str] = {}
    mechanism_stats: dict[str, dict[str, Any]] = {}

    for mech in mechanism_vars:
        m_idx = idx[mech]
        obs_stat = _binary_association(obs_data[:, m_idx], y_sec_obs)
        probe = probe_map.get(mech)
        if probe is not None:
            p_idx = idx[probe]
            other_probes = [idx[p] for p in probe_vars if p != probe]
            if other_probes:
                clean_mask = np.all(arr_data[:, other_probes] == 0, axis=1)
                sub_p = arr_data[clean_mask, p_idx]
                sub_y = y_sec_all[clean_mask]
                if np.count_nonzero(sub_p == 1) >= 2 and np.count_nonzero(sub_p == 0) >= 2:
                    probe_stat = _binary_association(sub_p, sub_y)
                else:
                    probe_stat = _binary_association(arr_data[:, p_idx], y_sec_all)
            else:
                probe_stat = _binary_association(arr_data[:, p_idx], y_sec_all)
        else:
            probe_stat = {"delta": obs_stat["delta"], "p_value": obs_stat["p_value"], "n1": 0, "n0": 0}

        if valid_pag and pag_arr is not None:
            adj_sec = bool(pag_arr[m_idx, idx_y_sec] != 0)
            directed_to_sec = nx.has_path(directed, m_idx, idx_y_sec)
            bidirected_sec = bool(adj_sec and pag_arr[m_idx, idx_y_sec] == 2 and pag_arr[idx_y_sec, m_idx] == 2)
            circle_to_sec = bool(adj_sec and pag_arr[m_idx, idx_y_sec] == 2 and pag_arr[idx_y_sec, m_idx] == 1)
            mark_pair = [int(pag_arr[m_idx, idx_y_sec]), int(pag_arr[idx_y_sec, m_idx])]
        else:
            adj_sec = False
            directed_to_sec = False
            bidirected_sec = False
            circle_to_sec = False
            mark_pair = [0, 0]

        effect_delta = probe_stat["delta"] if probe is not None else obs_stat["delta"]
        if directed_to_sec and effect_delta > 0.0:
            role = "causal_security_driver"
        elif bidirected_sec:
            role = "latent_confounded_proxy"
        elif circle_to_sec:
            role = "unconfirmed_ambiguous"
        elif abs(obs_stat["delta"]) >= min_corr or obs_stat["p_value"] <= alpha:
            role = "environment_confounded_proxy"
        else:
            role = "inactive_or_null"

        classifications[mech] = role
        mechanism_stats[mech] = {
            "role": role,
            "probe_var": probe,
            "edge_marks_to_security": mark_pair,
            "adjacent_to_security": adj_sec,
            "directed_path_to_security": directed_to_sec,
            "obs_delta_security": float(obs_stat["delta"]),
            "obs_p_value": float(obs_stat["p_value"]),
            "probe_delta_security": float(probe_stat["delta"]),
            "probe_p_value": float(probe_stat["p_value"]),
        }

    scope_bleed_hazards: list[dict[str, Any]] = []
    if functional_sink in idx:
        idx_y_func = idx[functional_sink]
        y_func_all = arr_data[:, idx_y_func]
        candidates = [v for v in ([flat_probe_var] if flat_probe_var else []) + list(bleed_vars) if v in idx]
        seen_cands: set[str] = set()
        for var_name in candidates:
            if var_name in seen_cands:
                continue
            seen_cands.add(var_name)
            v_idx = idx[var_name]
            stat = _binary_association(arr_data[:, v_idx], y_func_all)
            has_path = bool(valid_pag and directed.has_node(v_idx) and nx.has_path(directed, v_idx, idx_y_func))
            if (has_path and stat["delta"] < 0.0) or (stat["delta"] <= -min_corr and stat["p_value"] <= alpha):
                scope_bleed_hazards.append(
                    {
                        "variable": var_name,
                        "directed_path_to_functional_sink": has_path,
                        "delta_functional": float(stat["delta"]),
                        "p_value": float(stat["p_value"]),
                    }
                )

    causal_drivers = sorted(
        (m for m, role in classifications.items() if role == "causal_security_driver"),
        key=lambda m: (-mechanism_stats[m]["probe_delta_security"], mechanism_stats[m]["probe_p_value"], m),
    )
    if max_mechanisms is not None:
        jci_selected = causal_drivers[:max_mechanisms]
        corr_budget = max_mechanisms
    else:
        jci_selected = causal_drivers
        corr_budget = max(1, len(causal_drivers))

    corr_candidates = sorted(
        (
            m
            for m in mechanism_vars
            if mechanism_stats[m]["obs_delta_security"] > 0.0
            and (mechanism_stats[m]["obs_delta_security"] >= min_corr or mechanism_stats[m]["obs_p_value"] <= alpha)
        ),
        key=lambda m: (-mechanism_stats[m]["obs_delta_security"], mechanism_stats[m]["obs_p_value"], m),
    )
    corr_selected = corr_candidates[:corr_budget]
    scope_bleed_detected = bool(scope_bleed_hazards)

    return {
        "pag_valid": bool(valid_pag),
        "direction_checks": {
            "valid": bool(checks["valid"]),
            "is_dag": bool(checks["is_dag"]),
            "no_arrows_into_context": bool(checks["no_arrows_into_context"]),
            "no_tails_out_of_sinks": bool(checks["no_tails_out_of_sinks"]),
        },
        "classifications": classifications,
        "mechanism_stats": mechanism_stats,
        "scope_bleed_detected": scope_bleed_detected,
        "scope_bleed_hazards": scope_bleed_hazards,
        "jci_policy": {
            "selected_mechanisms": jci_selected,
            "abstained": len(jci_selected) == 0,
            "recommended_mode": "tsg_scoped" if scope_bleed_detected else "flat",
        },
        "corr_policy": {
            "selected_mechanisms": corr_selected,
            "abstained": len(corr_selected) == 0,
            "recommended_mode": "tsg_scoped",
        },
    }


def evaluate_paired_counterfactuals(
    task_outcomes: Sequence[Mapping[str, Mapping[str, Any]]],
    *,
    arms: Sequence[str] = ("baseline", "corr_tsg", "jci_flat", "jci_tsg"),
    comparisons: Sequence[dict[str, Any]] | None = None,
    alpha: float = 0.05,
    practical_margin: float = 0.05,
) -> dict[str, Any]:
    """Compute within-task paired counterfactual ITT statistics across declared arms."""
    n = len(task_outcomes)
    if n < 2:
        raise ValueError("Paired counterfactual evaluation requires at least 2 task units")

    if comparisons is None:
        comparisons = [
            {"id": "jci_tsg_vs_baseline", "arm_a": "jci_tsg", "arm_b": "baseline", "endpoint": "joint", "primary": True},
            {"id": "jci_tsg_vs_corr_tsg", "arm_a": "jci_tsg", "arm_b": "corr_tsg", "endpoint": "joint", "primary": True},
            {"id": "jci_tsg_vs_jci_flat", "arm_a": "jci_tsg", "arm_b": "jci_flat", "endpoint": "joint", "primary": True},
            {"id": "jci_tsg_vs_jci_flat_func", "arm_a": "jci_tsg", "arm_b": "jci_flat", "endpoint": "functionality", "primary": False},
            {"id": "jci_tsg_vs_corr_tsg_sec", "arm_a": "jci_tsg", "arm_b": "corr_tsg", "endpoint": "secure_yield", "primary": False},
        ]

    arm_rates: dict[str, dict[str, Any]] = {}
    vectors: dict[str, dict[str, np.ndarray]] = {arm: {} for arm in arms}
    for arm in arms:
        code_valid = np.array([int(row[arm]["code_valid"]) for row in task_outcomes], dtype=float)
        oracle_eval = np.array([int(row[arm]["oracle_evaluable"]) for row in task_outcomes], dtype=float)
        unknown_sec = np.array(
            [int(int(row[arm]["code_valid"]) == 1 and int(row[arm]["oracle_evaluable"]) == 0) for row in task_outcomes],
            dtype=float,
        )
        sec_yield = np.array([int(row[arm]["secure_yield"]) for row in task_outcomes], dtype=float)
        func_pass = np.array(
            [1.0 if row[arm].get("functionality") == 1 else 0.0 for row in task_outcomes],
            dtype=float,
        )
        unknown_func = np.array(
            [1.0 if row[arm].get("functionality") is None else 0.0 for row in task_outcomes],
            dtype=float,
        )
        joint = np.array(
            [1.0 if (int(row[arm]["secure_yield"]) == 1 and row[arm].get("functionality") == 1) else 0.0 for row in task_outcomes],
            dtype=float,
        )
        latent_joint_upper = np.array(
            [
                int(row[arm]["latent_joint_upper"])
                if "latent_joint_upper" in row[arm]
                else int(
                    (int(row[arm]["secure_yield"]) == 1 or (int(row[arm]["code_valid"]) == 1 and int(row[arm]["oracle_evaluable"]) == 0))
                    and row[arm].get("functionality") != 0
                    and int(row[arm]["code_valid"]) == 1
                )
                for row in task_outcomes
            ],
            dtype=float,
        )
        vectors[arm] = {
            "code_valid": code_valid,
            "oracle_evaluable": oracle_eval,
            "unknown_security": unknown_sec,
            "secure_yield": sec_yield,
            "functionality": func_pass,
            "joint": joint,
        }
        arm_rates[arm] = {
            "n_tasks": n,
            "code_valid_rate": float(np.mean(code_valid)),
            "oracle_evaluable_rate": float(np.mean(oracle_eval)),
            "unknown_security_rate": float(np.mean(unknown_sec)),
            "secure_yield_rate": float(np.mean(sec_yield)),
            "functional_pass_rate": float(np.mean(func_pass)),
            "unknown_functional_rate": float(np.mean(unknown_func)),
            "joint_success_rate": float(np.mean(joint)),
            "latent_joint_upper_rate": float(np.mean(latent_joint_upper)),
        }

    n_primary = max(1, sum(1 for item in comparisons if item.get("primary", False)))
    t_nom = float(t.ppf(1.0 - alpha / 2.0, df=n - 1))
    t_bonf = float(t.ppf(1.0 - alpha / (2.0 * n_primary), df=n - 1))

    comparison_results: list[dict[str, Any]] = []
    for item in comparisons:
        arm_a = item["arm_a"]
        arm_b = item["arm_b"]
        endpoint = item["endpoint"]
        ya = vectors[arm_a][endpoint]
        yb = vectors[arm_b][endpoint]
        diff = ya - yb
        estimate = float(np.mean(diff))
        sd = float(np.std(diff, ddof=1)) if n > 1 else 0.0
        se = sd / math.sqrt(n)
        ci_low = estimate - t_nom * se
        ci_high = estimate + t_nom * se
        bonf_low = estimate - t_bonf * se
        bonf_high = estimate + t_bonf * se
        n_win = int(np.count_nonzero(diff > 0.0))
        n_loss = int(np.count_nonzero(diff < 0.0))
        n_tie = int(np.count_nonzero(diff == 0.0))
        sign_p = float(binomtest(n_win, n_win + n_loss, 0.5).pvalue) if (n_win + n_loss) > 0 else 1.0

        var_a = float(np.var(ya, ddof=1)) if n > 1 else 0.0
        var_b = float(np.var(yb, ddof=1)) if n > 1 else 0.0
        unpaired_se = math.sqrt((var_a + var_b) / n)
        pairing_vr = 1.0 - (se * se) / (unpaired_se * unpaired_se) if unpaired_se > 1e-12 else 0.0

        comparison_results.append(
            {
                "id": item["id"],
                "arm_a": arm_a,
                "arm_b": arm_b,
                "endpoint": endpoint,
                "primary": bool(item.get("primary", False)),
                "n_tasks": n,
                "estimate": estimate,
                "sd": sd,
                "se": se,
                "ci_low": ci_low,
                "ci_high": ci_high,
                "bonferroni_low": bonf_low,
                "bonferroni_high": bonf_high,
                "n_win": n_win,
                "n_loss": n_loss,
                "n_tie": n_tie,
                "sign_test_p_value": sign_p,
                "unpaired_se_equivalent": unpaired_se,
                "pairing_variance_reduction": float(pairing_vr),
                "significant_positive": bool(ci_low > 0.0),
                "practically_positive": bool(bonf_low > 0.0 and estimate >= practical_margin),
                "harm_against_a": bool(ci_high < 0.0),
            }
        )

    return {
        "n_tasks": n,
        "alpha": float(alpha),
        "practical_margin": float(practical_margin),
        "n_primary_comparisons": n_primary,
        "arm_rates": arm_rates,
        "comparisons": comparison_results,
    }


def _simulate_discovery_and_eval(
    *,
    scenario: str,
    batch_seed: int,
    rep_index: int,
    plan: Mapping[str, Any],
) -> tuple[dict[str, Any], dict[str, Any], np.ndarray]:
    if scenario not in MECHANISM_SCENARIOS:
        raise ValueError(f"Unknown mechanism scenario: {scenario}")

    if scenario == "confounded_and_scoped":
        p_shared, b_env, b_u, b_cau, b_bleed = 0.60, 2.0, 3.2, 2.2, 2.8
    elif scenario == "pure_latent_trap":
        p_shared, b_env, b_u, b_cau, b_bleed = 0.50, 0.8, 3.6, 2.3, 2.4
    elif scenario == "multi_op_high_interference":
        p_shared, b_env, b_u, b_cau, b_bleed = 0.85, 1.8, 3.2, 2.2, 3.2
    else:  # null_spurious_only
        p_shared, b_env, b_u, b_cau, b_bleed = 0.55, 1.7, 3.0, 0.0, 2.6

    disc_seed = int.from_bytes(
        bytes.fromhex(content_hash({"batch_seed": batch_seed, "scenario": scenario, "rep": rep_index, "split": "disc"}))[:8],
        "big",
    )
    eval_seed = int.from_bytes(
        bytes.fromhex(content_hash({"batch_seed": batch_seed, "scenario": scenario, "rep": rep_index, "split": "eval"}))[:8],
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
    z_env = rng_disc.binomial(1, _sigmoid(-1.8 + 3.6 * c_env))
    z_lat = rng_disc.binomial(1, _sigmoid(-2.0 + 3.8 * u_lat + 3.4 * i_lat))
    z_cau = rng_disc.binomial(1, _sigmoid(-1.4 - 0.6 * c_env + 3.4 * i_cau))
    z_bleed = rng_disc.binomial(1, _sigmoid(-2.8 + 3.6 * (i_flat * z_shared) + 0.5 * i_flat))

    y_sec = rng_disc.binomial(1, _sigmoid(-2.4 + b_env * c_env + b_u * u_lat + b_cau * z_cau))
    y_func = rng_disc.binomial(1, _sigmoid(2.0 - b_bleed * z_bleed))

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

    def _apply_policy(
        selected: Sequence[str],
        mode: str,
        *,
        c_e: np.ndarray,
        u_e: np.ndarray,
        z_sh_e: np.ndarray,
        noise_lat: np.ndarray,
        noise_cau: np.ndarray,
        noise_bleed: np.ndarray,
        noise_sec: np.ndarray,
        noise_func: np.ndarray,
    ) -> list[dict[str, Any]]:
        act_lat = 1 if "Z_lat" in selected else 0
        act_cau = 1 if "Z_cau" in selected else 0
        act_flat = 1 if (mode == "flat" and len(selected) > 0) else 0

        p_cau = _sigmoid(-1.4 - 0.6 * c_e + 3.4 * act_cau)
        z_c_val = (noise_cau < p_cau).astype(int)
        _ = (noise_lat < _sigmoid(-2.0 + 3.8 * u_e + 3.4 * act_lat)).astype(int)
        p_bleed = _sigmoid(-2.8 + 3.6 * (act_flat * z_sh_e) + 0.5 * act_flat)
        z_b_val = (noise_bleed < p_bleed).astype(int)
        p_sec = _sigmoid(-2.4 + b_env * c_e + b_u * u_e + b_cau * z_c_val)
        p_func = _sigmoid(2.0 - b_bleed * z_b_val)
        sec_arr = (noise_sec < p_sec).astype(int)
        func_arr = (noise_func < p_func).astype(int)
        return [
            {
                "code_valid": 1,
                "oracle_evaluable": 1,
                "secure_yield": int(s),
                "functionality": int(f),
                "joint": int(s == 1 and f == 1),
                "latent_joint_upper": int(s == 1 and f == 1),
            }
            for s, f in zip(sec_arr, func_arr)
        ]

    n_eval = int(plan["n_eval"])
    c_e = rng_eval.binomial(1, 0.50, size=n_eval)
    u_e = rng_eval.binomial(1, 0.50, size=n_eval)
    z_sh_e = rng_eval.binomial(1, p_shared, size=n_eval)
    # Common random numbers across paired counterfactual arms for genuine task-level pairing.
    noise_lat = rng_eval.random(size=n_eval)
    noise_cau = rng_eval.random(size=n_eval)
    noise_bleed = rng_eval.random(size=n_eval)
    noise_sec = rng_eval.random(size=n_eval)
    noise_func = rng_eval.random(size=n_eval)

    def _eval_arm(selected: Sequence[str], mode: str) -> list[dict[str, Any]]:
        return _apply_policy(
            selected,
            mode,
            c_e=c_e,
            u_e=u_e,
            z_sh_e=z_sh_e,
            noise_lat=noise_lat,
            noise_cau=noise_cau,
            noise_bleed=noise_bleed,
            noise_sec=noise_sec,
            noise_func=noise_func,
        )

    return (
        {"labels": labels, "context_vars": ["C_env", "I_lat", "I_cau", "I_flat"], "sink_vars": ["Y_sec", "Y_func"]},
        {
            "eval_fn_inputs": {
                "eval_arm": _eval_arm,
            },
            "n_eval": n_eval,
        },
        data,
    )


def _run_cell_worker(args: tuple[str, int, int, Mapping[str, Any], str | None]) -> dict[str, Any]:
    scenario, batch_seed, rep_index, plan, rscript = args
    meta, eval_bundle, data = _simulate_discovery_and_eval(
        scenario=scenario,
        batch_seed=batch_seed,
        rep_index=rep_index,
        plan=plan,
    )
    ci_seed = int.from_bytes(
        bytes.fromhex(content_hash({"batch_seed": batch_seed, "scenario": scenario, "rep": rep_index, "role": "ci"}))[:8],
        "big",
    )
    ci = ConditionalPermutation(data, meta["labels"], draws=int(plan["ci_draws"]), seed=ci_seed)
    backend = StructureBackend(rscript=rscript)
    try:
        pag_result = backend.search(
            meta["labels"],
            "python-jci12",
            ci,
            float(plan["ci_alpha"]),
            max_order=int(plan["maximum_skeleton_conditioning_order"]),
            context_vars=meta["context_vars"],
            sink_vars=meta["sink_vars"],
            on_insufficient_ci="conservative",
        )
    finally:
        backend.close()

    discovery = classify_jci_mechanisms(
        pag_result,
        data=data,
        labels=meta["labels"],
        context_vars=meta["context_vars"],
        probe_map={"Z_lat": "I_lat", "Z_cau": "I_cau"},
        mechanism_vars=["Z_env", "Z_lat", "Z_cau"],
        security_sink="Y_sec",
        functional_sink="Y_func",
        flat_probe_var="I_flat",
        bleed_vars=["Z_bleed"],
        alpha=float(plan["ci_alpha"]),
    )
    jci_selected = discovery["jci_policy"]["selected_mechanisms"]
    corr_selected = discovery["corr_policy"]["selected_mechanisms"]

    eval_arm = eval_bundle["eval_fn_inputs"]["eval_arm"]
    arm_rows = {
        "baseline": eval_arm([], "baseline"),
        "corr_tsg": eval_arm(corr_selected, "tsg_scoped"),
        "jci_flat": eval_arm(jci_selected, "flat"),
        "jci_tsg": eval_arm(jci_selected, "tsg_scoped"),
    }
    n_eval = int(plan["n_eval"])
    task_outcomes = [{arm: arm_rows[arm][i] for arm in arm_rows} for i in range(n_eval)]
    paired = evaluate_paired_counterfactuals(
        task_outcomes,
        alpha=float(plan["eval_alpha"]),
        practical_margin=float(plan["practical_margin"]),
    )

    true_drivers = [] if scenario == "null_spurious_only" else ["Z_cau"]
    false_pos_jci = len(set(jci_selected) - set(true_drivers))
    false_pos_corr = len(set(corr_selected) - set(true_drivers))

    return {
        "scenario": scenario,
        "batch_seed": batch_seed,
        "rep_index": rep_index,
        "cell_id": f"{scenario}_s{batch_seed}_r{rep_index:02d}",
        "n_ci_queries": len(ci.cache),
        "pag": pag_result,
        "discovery": discovery,
        "false_positive_jci": false_pos_jci,
        "false_positive_corr": false_pos_corr,
        "true_driver_recall_jci": 1.0 if set(true_drivers) <= set(jci_selected) else 0.0,
        "true_driver_recall_corr": 1.0 if set(true_drivers) <= set(corr_selected) else 0.0,
        "paired": paired,
    }


def _aggregate_mechanism_summary(
    plan: Mapping[str, Any],
    cells: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    by_scenario: dict[str, list[Mapping[str, Any]]] = {}
    for cell in cells:
        by_scenario.setdefault(str(cell["scenario"]), []).append(cell)

    scenario_summaries: dict[str, dict[str, Any]] = {}
    for scenario, rows in sorted(by_scenario.items()):
        comp_ids = [item["id"] for item in rows[0]["paired"]["comparisons"]]
        comp_stats: dict[str, dict[str, Any]] = {}
        for cid in comp_ids:
            matched = [next(c for c in r["paired"]["comparisons"] if c["id"] == cid) for r in rows]
            comp_stats[cid] = {
                "mean_estimate": float(np.mean([m["estimate"] for m in matched])),
                "mean_se": float(np.mean([m["se"] for m in matched])),
                "mean_pairing_vr": float(np.mean([m["pairing_variance_reduction"] for m in matched])),
                "significant_positive_cells": int(sum(1 for m in matched if m["significant_positive"])),
                "practically_positive_cells": int(sum(1 for m in matched if m["practically_positive"])),
                "harm_cells": int(sum(1 for m in matched if m["harm_against_a"])),
                "total_cells": len(rows),
            }

        arm_means: dict[str, dict[str, float]] = {}
        for arm in rows[0]["paired"]["arm_rates"]:
            arm_means[arm] = {
                metric: float(np.mean([r["paired"]["arm_rates"][arm][metric] for r in rows]))
                for metric in ("secure_yield_rate", "functional_pass_rate", "joint_success_rate")
            }

        scenario_summaries[scenario] = {
            "n_cells": len(rows),
            "total_ci_queries": int(sum(int(r["n_ci_queries"]) for r in rows)),
            "jci_false_discovery_cells": int(sum(1 for r in rows if r["false_positive_jci"] > 0)),
            "corr_false_discovery_cells": int(sum(1 for r in rows if r["false_positive_corr"] > 0)),
            "jci_true_driver_recall": float(np.mean([r["true_driver_recall_jci"] for r in rows])),
            "corr_true_driver_recall": float(np.mean([r["true_driver_recall_corr"] for r in rows])),
            "jci_abstention_rate": float(np.mean([1.0 if r["discovery"]["jci_policy"]["abstained"] else 0.0 for r in rows])),
            "scope_bleed_detection_rate": float(np.mean([1.0 if r["discovery"]["scope_bleed_detected"] else 0.0 for r in rows])),
            "arm_mean_rates": arm_means,
            "comparisons": comp_stats,
        }

    null_summary = scenario_summaries.get("null_spurious_only")
    null_clean = True if null_summary is None else (null_summary["jci_false_discovery_cells"] == 0)
    active_scenarios = [s for s in scenario_summaries if s != "null_spurious_only"]
    jci_beats_corr_everywhere = all(
        scenario_summaries[s]["comparisons"]["jci_tsg_vs_corr_tsg"]["mean_estimate"] > 0.0
        for s in active_scenarios
    )
    jci_tsg_beats_flat_everywhere = all(
        scenario_summaries[s]["comparisons"]["jci_tsg_vs_jci_flat"]["mean_estimate"] > 0.0
        for s in active_scenarios
    )

    return {
        "study_id": plan["study_id"],
        "study_mode": plan["study_mode"],
        "formal_claim_allowed": False,
        "new_provider_calls": 0,
        "n_cells": len(cells),
        "total_ci_queries": int(sum(int(c["n_ci_queries"]) for c in cells)),
        "scenario_summaries": scenario_summaries,
        "verdict": {
            "null_control_abstention_passed": bool(null_clean),
            "jci_outperforms_corr_on_joint": bool(jci_beats_corr_everywhere),
            "tsg_outperforms_flat_on_joint": bool(jci_tsg_beats_flat_everywhere),
            "overall_passed": bool(null_clean and jci_beats_corr_everywhere and jci_tsg_beats_flat_everywhere),
        },
        "environment": {
            "python_version": platform.python_version(),
            "numpy_version": np.__version__,
            "scipy_version": scipy.__version__,
        },
    }


def run_mechanism_simulation_study(
    plan_path: Path,
    output_dir: Path,
    *,
    rscript: Path | None = None,
    workers: int = 1,
) -> dict[str, Any]:
    """Execute a complete verifiable Stage II mechanism discovery simulation study."""
    if type(workers) is not int or workers < 1:
        raise ValueError("workers must be a positive integer")
    out_dir = Path(output_dir)
    if out_dir.exists():
        raise FileExistsError(f"Output directory already exists: {out_dir}")
    plan = read_json(plan_path)
    validate_mechanism_plan(plan)

    jobs = [
        (scenario, seed, rep, plan, str(rscript) if rscript is not None else None)
        for scenario in plan["scenarios"]
        for seed in plan["batch_seeds"]
        for rep in range(int(plan.get("repetitions_per_seed", 1)))
    ]

    if workers == 1:
        cells = [_run_cell_worker(job) for job in jobs]
    else:
        with ProcessPoolExecutor(max_workers=workers) as pool:
            cells = list(pool.map(_run_cell_worker, jobs))

    summary = _aggregate_mechanism_summary(plan, cells)
    write_bundle(out_dir / "inputs", {"plan.json": plan})
    write_bundle(out_dir / "cells", {f"{cell['cell_id']}.json": cell for cell in cells})
    write_bundle(out_dir / "summary", {"result.json": summary})

    source_zip = out_dir / "source.zip"
    with zipfile.ZipFile(source_zip, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for rel in SOURCE_FILES:
            src_file = Path(rel)
            if src_file.is_file():
                zf.write(src_file, arcname=rel)

    manifest = {
        "study_id": plan["study_id"],
        "study_mode": plan["study_mode"],
        "plan_sha256": content_hash(plan),
        "summary_sha256": content_hash(summary),
        "source_zip_sha256": file_sha256(source_zip),
        "n_cells": len(cells),
        "cell_digests": {cell["cell_id"]: content_hash(cell) for cell in cells},
    }
    write_json_new(out_dir / "manifest.json", manifest)
    return {
        "status": "COMPLETED",
        "study_id": plan["study_id"],
        "n_cells": len(cells),
        "total_ci_queries": summary["total_ci_queries"],
        "verdict": summary["verdict"],
        "summary_sha256": manifest["summary_sha256"],
    }
