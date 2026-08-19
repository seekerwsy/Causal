"""Post-replication ITT and distribution diagnostics for independent validation."""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Any

from secaware.analysis.cluster_bootstrap import linear_percentile
from secaware.analysis.multiple_testing import bonferroni_percentile_quantiles
from secaware.experiments.held_out_policy_analysis import _verify_directory_manifest
from secaware.exploratory.independent_validation_run import _verify_manifest
from secaware.exploratory.randomized_discovery_bootstrap import _manifest
from secaware.exploratory.randomized_discovery_v2_fci import (
    _environment,
    _read_json,
    _write_json,
    _write_jsonl,
)
from secaware.io.jsonl import read_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.randomness import RNG_VERSION, DeterministicRNG

_SCHEMA_VERSION = "1.0"
_ARMS = (
    "target_patch",
    "noop_rewrite",
    "length_matched_placebo",
    "generic_security_reminder",
)
_OUTCOMES = (
    "z.target_mechanism_realized",
    "y.discovery_functional",
)
_CONTROLS = ("noop_rewrite", "length_matched_placebo", "generic_security_reminder")
_TREATMENT = "target_patch"


def _input_dir(repo_root: Path, record: object, *, recursive: bool) -> Path:
    if type(record) is not dict or set(record) != {"path", "sha256"}:
        raise ValueError("independent effects input record failed validation")
    path = (repo_root / str(record["path"])).resolve()
    try:
        path.relative_to(repo_root)
    except ValueError:
        raise ValueError("independent effects input escaped repository") from None
    manifest = path / "artifact-manifest.json"
    if not path.is_dir() or sha256_file(manifest) != record["sha256"]:
        raise ValueError("independent effects input digest failed validation")
    if recursive:
        _verify_manifest(manifest)
    else:
        _verify_directory_manifest(path)
    return path


def _validated_config(repo_root: Path, path: Path) -> tuple[dict[str, Any], Path, Path, Path]:
    config = _read_json(path)
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("analysis_id") != "five_cwe_independent_validation_effects_v1"
        or config.get("status") != "POST_REPLICATION_DIAGNOSTIC_FROZEN_BEFORE_EFFECT_COMPUTATION"
        or config.get("treatment_arm") != _TREATMENT
        or config.get("control_arms") != list(_CONTROLS)
        or config.get("outcomes") != list(_OUTCOMES)
        or config.get("bootstrap")
        != {
            "samples": 200,
            "confidence_level": 0.95,
            "percentile_method": "linear-v1",
            "global_seed": 2026081924,
            "unit": "complete_task_block",
            "multiplicity_method": "bonferroni_within_outcome_family",
            "family_size": 3,
        }
        or config.get("post_randomization_filtering") != "forbidden"
        or config.get("analysis_role") != "explanatory_not_preregistered_confirmation"
    ):
        raise ValueError("independent effects config failed validation")
    independent = _input_dir(repo_root, config.get("independent_table"), recursive=False)
    development = _input_dir(repo_root, config.get("development_table"), recursive=False)
    replication = _input_dir(repo_root, config.get("replication_result"), recursive=True)
    replication_report = _read_json(replication / "report.json")
    if (
        replication_report.get("status") != "INDEPENDENT_VALIDATION_BOOTSTRAP_COMPLETE"
        or replication_report.get("replication_decision") != "not_replicated"
        or replication_report.get("successful_replicates") != 200
        or replication_report.get("failed_replicates") != 0
    ):
        raise ValueError("independent effects replication input failed validation")
    return config, independent, development, replication


def _blocks(
    rows: list[dict[str, Any]], *, expected_tasks: int
) -> dict[str, dict[str, dict[str, Any]]]:
    blocks: dict[str, dict[str, dict[str, Any]]] = {}
    for row in rows:
        task_id = str(row["task_id"])
        arm = str(row["arm_role"])
        if arm not in _ARMS or arm in blocks.setdefault(task_id, {}):
            raise ValueError("independent effects task block failed validation")
        values = row.get("values")
        if type(values) is not dict or any(
            values.get(outcome) not in {0, 1} for outcome in _OUTCOMES
        ):
            raise ValueError("independent effects outcome failed validation")
        blocks[task_id][arm] = row
    if len(blocks) != expected_tasks or any(set(block) != set(_ARMS) for block in blocks.values()):
        raise ValueError("independent effects task closure failed validation")
    return blocks


def _association(rows: list[dict[str, Any]]) -> dict[str, object]:
    counts = Counter(
        (
            int(row["values"]["z.target_mechanism_realized"]),
            int(row["values"]["y.discovery_functional"]),
        )
        for row in rows
    )
    z0 = counts[(0, 0)] + counts[(0, 1)]
    z1 = counts[(1, 0)] + counts[(1, 1)]
    if z0 == 0 or z1 == 0:
        raise ValueError("independent effects association support failed validation")
    y_z0 = counts[(0, 1)] / z0
    y_z1 = counts[(1, 1)] / z1
    return {
        "contingency_z_by_y": [
            [counts[(0, 0)], counts[(0, 1)]],
            [counts[(1, 0)], counts[(1, 1)]],
        ],
        "functional_rate_z0": y_z0,
        "functional_rate_z1": y_z1,
        "unadjusted_risk_difference_z1_minus_z0": y_z1 - y_z0,
    }


def _draws(
    *,
    task_ids: tuple[str, ...],
    samples: int,
    seed_content: dict[str, object],
) -> tuple[tuple[str, ...], ...]:
    rng = DeterministicRNG(bytes.fromhex(canonical_sha256(seed_content)))
    return tuple(tuple(rng.choice(task_ids) for _ in task_ids) for _ in range(samples))


def analyze_independent_validation_effects(
    *,
    repo_root: Path,
    config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    config_path = config_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ValueError("independent effects output already exists")
    config, independent_dir, development_dir, replication_dir = _validated_config(
        repo_root, config_path
    )
    independent_rows = read_jsonl(
        independent_dir / "combined-rows.jsonl", required=True, allow_empty=False
    )
    development_rows = [
        row
        for row in read_jsonl(
            development_dir / "combined-rows.jsonl", required=True, allow_empty=False
        )
        if row.get("model_id") == "phi-4-14b"
    ]
    if len(independent_rows) != 220 or len(development_rows) != 372:
        raise ValueError("independent effects population failed validation")
    independent_blocks = _blocks(independent_rows, expected_tasks=55)
    _blocks(development_rows, expected_tasks=93)
    task_ids = tuple(sorted(independent_blocks))
    bootstrap = config["bootstrap"]
    effects: list[dict[str, object]] = []
    draw_rows: list[dict[str, object]] = []
    flips: list[dict[str, object]] = []
    low_q, high_q = bonferroni_percentile_quantiles(
        confidence_level=float(bootstrap["confidence_level"]),
        number_of_pre_registered_contrasts=int(bootstrap["family_size"]),
    )
    for outcome in _OUTCOMES:
        for control in _CONTROLS:
            task_differences = {
                task_id: int(block[_TREATMENT]["values"][outcome])
                - int(block[control]["values"][outcome])
                for task_id, block in independent_blocks.items()
            }
            point = sum(task_differences.values()) / len(task_differences)
            seed_content = {
                "schema_version": _SCHEMA_VERSION,
                "seed_kind": "independent-validation-effect-task-bootstrap-v1",
                "global_seed": bootstrap["global_seed"],
                "config_sha256": sha256_file(config_path),
                "outcome": outcome,
                "treatment": _TREATMENT,
                "control": control,
                "task_ids": list(task_ids),
            }
            sampled_tasks = _draws(
                task_ids=task_ids,
                samples=int(bootstrap["samples"]),
                seed_content=seed_content,
            )
            estimates = tuple(
                sum(task_differences[task_id] for task_id in draw) / len(draw)
                for draw in sampled_tasks
            )
            ci_low = linear_percentile(estimates, low_q, method="linear-v1")
            ci_high = linear_percentile(estimates, high_q, method="linear-v1")
            changes = Counter(
                "improved" if value > 0 else "harmed" if value < 0 else "unchanged"
                for value in task_differences.values()
            )
            effect_content = {
                "schema_version": _SCHEMA_VERSION,
                "outcome_id": outcome,
                "treatment_arm": _TREATMENT,
                "control_arm": control,
                "independent_tasks": len(task_ids),
                "treatment_rate": sum(
                    int(block[_TREATMENT]["values"][outcome])
                    for block in independent_blocks.values()
                )
                / len(task_ids),
                "control_rate": sum(
                    int(block[control]["values"][outcome]) for block in independent_blocks.values()
                )
                / len(task_ids),
                "itt_risk_difference": point,
                "simultaneous_ci_low": ci_low,
                "simultaneous_ci_high": ci_high,
                "confidence_level": bootstrap["confidence_level"],
                "multiplicity_method": "bonferroni",
                "family_size": bootstrap["family_size"],
                "bootstrap_samples": bootstrap["samples"],
                "interval_status": (
                    "positive" if ci_low > 0 else "negative" if ci_high < 0 else "inconclusive"
                ),
                "analysis_role": config["analysis_role"],
            }
            effect_id = "independent_effect_" + canonical_sha256(effect_content)
            effects.append({**effect_content, "effect_id": effect_id})
            draw_rows.extend(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "effect_id": effect_id,
                    "replicate_index": index,
                    "sampled_task_ids": list(draw),
                    "estimate": estimate,
                }
                for index, (draw, estimate) in enumerate(zip(sampled_tasks, estimates, strict=True))
            )
            flips.append(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "effect_id": effect_id,
                    "outcome_id": outcome,
                    "control_arm": control,
                    "improved": changes["improved"],
                    "harmed": changes["harmed"],
                    "unchanged": changes["unchanged"],
                    "flip_rate": (changes["improved"] + changes["harmed"]) / len(task_ids),
                    "net_improvement_rate": (changes["improved"] - changes["harmed"])
                    / len(task_ids),
                    "role": "diagnostic",
                }
            )
    independent_association = _association(independent_rows)
    development_association = _association(development_rows)
    association_draws = _draws(
        task_ids=task_ids,
        samples=int(bootstrap["samples"]),
        seed_content={
            "schema_version": _SCHEMA_VERSION,
            "seed_kind": "independent-validation-association-task-bootstrap-v1",
            "global_seed": bootstrap["global_seed"],
            "config_sha256": sha256_file(config_path),
            "task_ids": list(task_ids),
        },
    )
    association_estimates = []
    for draw in association_draws:
        sampled = [row for task_id in draw for row in independent_blocks[task_id].values()]
        association_estimates.append(
            float(_association(sampled)["unadjusted_risk_difference_z1_minus_z0"])
        )
    association_report = {
        "schema_version": _SCHEMA_VERSION,
        "interpretation": "unadjusted_association_not_causal_effect",
        "development": development_association,
        "independent_validation": {
            **independent_association,
            "cluster_bootstrap_ci_low": linear_percentile(
                association_estimates, 0.025, method="linear-v1"
            ),
            "cluster_bootstrap_ci_high": linear_percentile(
                association_estimates, 0.975, method="linear-v1"
            ),
        },
        "risk_difference_shift": float(
            independent_association["unadjusted_risk_difference_z1_minus_z0"]
        )
        - float(development_association["unadjusted_risk_difference_z1_minus_z0"]),
    }
    cwe_diagnostics = []
    for cwe in sorted({str(row["cwe"]) for row in independent_rows}):
        scoped = [block for block in independent_blocks.values() if block[_TREATMENT]["cwe"] == cwe]
        for outcome in _OUTCOMES:
            target = [int(block[_TREATMENT]["values"][outcome]) for block in scoped]
            noop = [int(block["noop_rewrite"]["values"][outcome]) for block in scoped]
            cwe_diagnostics.append(
                {
                    "schema_version": _SCHEMA_VERSION,
                    "cwe": cwe,
                    "outcome_id": outcome,
                    "task_clusters": len(scoped),
                    "target_rate": sum(target) / len(target),
                    "noop_rate": sum(noop) / len(noop),
                    "risk_difference": (sum(target) - sum(noop)) / len(target),
                    "role": "heterogeneity_diagnostic",
                    "confirmatory_status_allowed": False,
                }
            )
    effects.sort(key=lambda row: (str(row["outcome_id"]), str(row["control_arm"])))
    draw_rows.sort(key=lambda row: (str(row["effect_id"]), int(row["replicate_index"])))
    flips.sort(key=lambda row: (str(row["outcome_id"]), str(row["control_arm"])))
    cwe_diagnostics.sort(key=lambda row: (str(row["cwe"]), str(row["outcome_id"])))
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "effective-config.json", config)
    _write_jsonl(output_dir / "effects.jsonl", effects)
    _write_jsonl(output_dir / "bootstrap-draws.jsonl", draw_rows)
    _write_jsonl(output_dir / "task-flips.jsonl", flips)
    _write_jsonl(output_dir / "cwe-heterogeneity.jsonl", cwe_diagnostics)
    _write_json(output_dir / "mechanism-function-association-shift.json", association_report)
    _write_json(
        output_dir / "provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "config_sha256": sha256_file(config_path),
            "independent_table_manifest_sha256": config["independent_table"]["sha256"],
            "development_table_manifest_sha256": config["development_table"]["sha256"],
            "replication_manifest_sha256": config["replication_result"]["sha256"],
            "rng_version": RNG_VERSION,
            "post_randomization_filtered": 0,
        },
    )
    _write_json(output_dir / "environment.json", _environment())
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "INDEPENDENT_VALIDATION_EFFECT_DIAGNOSTICS_COMPLETE",
        "counts": {
            "tasks": len(task_ids),
            "assignments": len(independent_rows),
            "effects": len(effects),
            "bootstrap_draws": len(draw_rows),
            "cwe_diagnostics": len(cwe_diagnostics),
            "post_randomization_filtered": 0,
            "errors": 0,
            "pending": 0,
        },
        "effects": effects,
        "association_shift": association_report,
        "analysis_role": config["analysis_role"],
        "scientific_claim_allowed": False,
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


__all__ = ["analyze_independent_validation_effects"]
