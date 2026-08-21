"""Task-block bootstrap for one frozen mechanism-aware discovery-v2 path."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

import numpy as np

from secaware.causal.paths import edge_allows_possible_direction
from secaware.config import FCIDiscoveryConfig
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner
from secaware.experiments.held_out_policy_analysis import _verify_directory_manifest
from secaware.exploratory.randomized_discovery_bootstrap import (
    _canonical,
    _closed_replicate,
    _environment,
    _failure_reason,
    _manifest,
    _path_matches,
    _validated_pag,
    _write_json,
)
from secaware.exploratory.randomized_discovery_v2_fci import (
    _MECHANISM,
    _MODELS,
    _OUTCOME_BY_VIEW,
    _VIEWS,
    _base_background,
    _config,
    _edge_by_pair,
    _read_json,
    _table_and_matrix,
    _validated_analysis,
)
from secaware.exploratory.randomized_discovery_v2_fci import (
    _POLICY as _REFERENCE_POLICY,
)
from secaware.io.jsonl import write_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.randomness import RNG_VERSION, DeterministicRNG
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    PAGRecord,
    PAGRunKind,
    PathPatternRecord,
    VariableRole,
)

_SCHEMA_VERSION = "1.0"
_POLICY = "five-cwe-randomized-discovery-v2-task-block-bootstrap-v1"


def _reference_path(
    pag: PAGRecord,
    *,
    source: str,
    outcome: str,
) -> PathPatternRecord | None:
    checked = PAGRecord.model_validate(pag)
    edges = _edge_by_pair(checked)
    first = edges.get(frozenset({source, _MECHANISM}))
    second = edges.get(frozenset({_MECHANISM, outcome}))
    if (
        first is None
        or second is None
        or not edge_allows_possible_direction(first, source, _MECHANISM)
        or not edge_allows_possible_direction(second, _MECHANISM, outcome)
    ):
        return None
    variables = (source, _MECHANISM, outcome)
    marks = (
        first.marks_from(source, _MECHANISM),
        second.marks_from(_MECHANISM, outcome),
    )
    return PathPatternRecord.from_content(variable_ids=variables, endpoint_marks=marks)


def _model_stem(model_id: str) -> str:
    if model_id not in _MODELS:
        raise ValueError("discovery-v2 bootstrap model failed validation")
    return "qwen7b" if model_id.startswith("qwen") else "phi14b"


def _load_inputs(
    *,
    table_dir: Path,
    reference_dir: Path,
    analysis_config_path: Path,
    bootstrap_config_path: Path,
) -> tuple[
    CausalTableRecord,
    BackgroundKnowledgeRecord,
    PAGRecord,
    FCIDiscoveryConfig,
    tuple[tuple[str, tuple[dict[str, object], ...]], ...],
    dict[str, object],
    str,
    str,
    str,
]:
    table_manifest_sha256 = _verify_directory_manifest(table_dir)
    reference_manifest_sha256 = _verify_directory_manifest(reference_dir)
    analysis = _validated_analysis(analysis_config_path)
    bootstrap = _read_json(bootstrap_config_path)
    report = _read_json(reference_dir / "report.json")
    model_id = str(report.get("model_id"))
    view_id = str(report.get("view_id"))
    if (
        model_id not in _MODELS
        or view_id not in _VIEWS
        or report.get("status") != "DISCOVERY_V2_REFERENCE_FCI_COMPLETE"
        or report.get("raw_possible_xzy") is not True
        or report.get("candidate_source_variable")
        != analysis["candidate_freeze"]["source_variable"]
        or bootstrap
        != {
            "schema_version": "1.0",
            "bootstrap_id": "five_cwe_randomized_discovery_v2_bootstrap_qwen_joint_v1",
            "status": "FROZEN_AFTER_REFERENCE_PATH_BEFORE_BOOTSTRAP",
            "model_id": "qwen2.5-coder-7b-instruct",
            "view_id": "target_noop_joint",
            "source_variable": "c.arm",
            "mechanism_variable": _MECHANISM,
            "outcome_variable": "y.discovery_secure_functional",
            "global_seed": 2026081921,
            "bootstrap_samples": 200,
            "bootstrap_unit": "complete_task_block",
            "stability_threshold": 0.8,
            "max_failed_bootstrap_fraction": 0.1,
            "independent_validation_required": True,
            "scientific_claim_allowed": False,
        }
    ):
        raise ValueError("discovery-v2 bootstrap reference report failed validation")
    matrix_path = table_dir / f"matrix-{_model_stem(model_id)}-{view_id}.json"
    payload = _read_json(matrix_path)
    projection = tuple(str(item) for item in analysis["variable_projection_by_view"][view_id])
    producer_sha256 = canonical_sha256(
        {
            "policy": _REFERENCE_POLICY,
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "table_manifest_sha256": table_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
        }
    )
    table, full_matrix, bindings = _table_and_matrix(
        payload,
        producer_sha256=producer_sha256,
        projected_internal_ids=projection,
    )
    stored_table = type(table).model_validate(_read_json(reference_dir / "causal-table.json"))
    knowledge = _base_background(table)
    stored_knowledge = type(knowledge).model_validate(
        _read_json(reference_dir / "base-background-knowledge.json")
    )
    reference_pag = PAGRecord.model_validate(_read_json(reference_dir / "raw-pag.json"))
    config = _config(analysis)
    source = str(analysis["candidate_freeze"]["source_variable"])
    outcome = _OUTCOME_BY_VIEW[view_id]
    reference_path = _reference_path(reference_pag, source=source, outcome=outcome)
    if (
        table != stored_table
        or knowledge != stored_knowledge
        or reference_pag.run_kind is not PAGRunKind.JCI_RAW
        or reference_pag.table_id != table.table_id
        or reference_path is None
        or config.bootstrap_samples != 200
        or config.stability_threshold != 0.8
        or config.max_failed_bootstrap_fraction != 0.1
        or full_matrix.shape != (table.row_count, len(table.variables))
    ):
        raise ValueError("discovery-v2 bootstrap frozen inputs failed validation")
    arm_index = tuple(item.variable_id for item in table.variables).index("c.arm")
    expected_arms = (0, 1) if view_id.startswith("target_noop") else (0, 1, 2, 3)
    grouped: dict[str, list[dict[str, object]]] = {}
    for binding in bindings:
        grouped.setdefault(str(binding["task_id"]), []).append(binding)
    blocks = []
    for task_id in sorted(grouped):
        block = tuple(sorted(grouped[task_id], key=lambda item: item["values"][arm_index]))
        if tuple(item["values"][arm_index] for item in block) != expected_arms:
            raise ValueError("discovery-v2 complete arm block failed validation")
        blocks.append((task_id, block))
    if len(blocks) != table.independent_task_count or len(blocks) != 51:
        raise ValueError("discovery-v2 task population failed validation")
    pre_analysis_indices = tuple(
        index
        for index, item in enumerate(table.variables)
        if item.role in {VariableRole.W, VariableRole.C, VariableRole.X, VariableRole.P}
    )
    sampling_frame_sha256 = canonical_sha256(
        {
            "policy": _POLICY,
            "model_id": model_id,
            "view_id": view_id,
            "blocks": [
                {
                    "task_id": task_id,
                    "assignments": [
                        {
                            "assignment_id": item["assignment_id"],
                            "pre_analysis_values": [
                                item["values"][index] for index in pre_analysis_indices
                            ],
                        }
                        for item in block
                    ],
                }
                for task_id, block in blocks
            ],
        }
    )
    provenance: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "policy": _POLICY,
        "table_manifest_sha256": table_manifest_sha256,
        "reference_manifest_sha256": reference_manifest_sha256,
        "analysis_config_sha256": sha256_file(analysis_config_path),
        "bootstrap_config_sha256": sha256_file(bootstrap_config_path),
        "matrix_artifact_sha256": sha256_file(matrix_path),
        "table_sha256": table.table_sha256,
        "reference_pag_id": reference_pag.pag_id,
        "reference_path_id": reference_path.path_id,
        "background_knowledge_sha256": knowledge.knowledge_sha256,
        "sampling_frame_sha256": sampling_frame_sha256,
        "global_seed": bootstrap["global_seed"],
        "rng_version": RNG_VERSION,
        "candidate_path_source": "raw_pag",
        "jci_role": "secondary_orientation_sensitivity_only",
    }
    return (
        table,
        knowledge,
        reference_pag,
        config,
        tuple(blocks),
        provenance,
        source,
        outcome,
        view_id,
    )


def _draw(
    *,
    blocks: tuple[tuple[str, tuple[dict[str, object], ...]], ...],
    provenance: dict[str, object],
    replicate_index: int,
    variable_count: int,
) -> tuple[dict[str, object], np.ndarray]:
    seed_material = _canonical(
        {
            "schema_version": _SCHEMA_VERSION,
            "policy": _POLICY,
            "global_seed": provenance["global_seed"],
            "sampling_frame_sha256": provenance["sampling_frame_sha256"],
            "replicate_index": replicate_index,
        }
    )
    rng = DeterministicRNG(seed_material)
    selected = tuple(rng.choice(blocks) for _ in blocks)
    matrix_rows = []
    coordinates = []
    for draw_index, (task_id, block) in enumerate(selected):
        for arm_position, item in enumerate(block):
            matrix_rows.append(tuple(int(value) for value in item["values"]))
            coordinates.append(
                {
                    "draw_index": draw_index,
                    "arm_position": arm_position,
                    "task_id": task_id,
                    "assignment_id": item["assignment_id"],
                    "row_id": item["row_id"],
                }
            )
    matrix = np.asarray(matrix_rows, dtype=np.int64)
    if matrix.shape != (sum(len(item[1]) for item in selected), variable_count):
        raise ValueError("discovery-v2 bootstrap matrix failed validation")
    matrix = np.array(matrix, dtype=np.int64, order="C", copy=True)
    matrix.flags.writeable = False
    draw: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "replicate_index": replicate_index,
        "rng_version": RNG_VERSION,
        "seed_material_sha256": hashlib.sha256(seed_material).hexdigest(),
        "sampled_task_ids": [item[0] for item in selected],
        "row_coordinates": coordinates,
        "matrix_sha256": hashlib.sha256(matrix.tobytes(order="C")).hexdigest(),
    }
    draw["draw_sha256"] = canonical_sha256(draw)
    return draw, matrix


def run_randomized_discovery_v2_bootstrap(
    *,
    table_dir: Path,
    reference_dir: Path,
    analysis_config_path: Path,
    bootstrap_config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
    engineering_replicates: int | None = None,
    runner: FCIRunner | None = None,
) -> dict[str, object]:
    table_dir = table_dir.resolve()
    reference_dir = reference_dir.resolve()
    analysis_config_path = analysis_config_path.resolve()
    bootstrap_config_path = bootstrap_config_path.resolve()
    output_dir = output_dir.resolve()
    (
        table,
        knowledge,
        reference_pag,
        config,
        blocks,
        provenance,
        source,
        outcome,
        view_id,
    ) = _load_inputs(
        table_dir=table_dir,
        reference_dir=reference_dir,
        analysis_config_path=analysis_config_path,
        bootstrap_config_path=bootstrap_config_path,
    )
    reference_path = _reference_path(reference_pag, source=source, outcome=outcome)
    if reference_path is None:
        raise ValueError("discovery-v2 bootstrap reference path failed validation")
    if engineering_replicates is None:
        planned_replicates = config.bootstrap_samples
        eligible_to_freeze = True
    elif type(engineering_replicates) is int and 1 <= engineering_replicates <= 10:
        planned_replicates = engineering_replicates
        eligible_to_freeze = False
    else:
        raise ValueError("discovery-v2 engineering replicate bound failed validation")
    run_config = {
        **provenance,
        "planned_replicates": planned_replicates,
        "configured_bootstrap_samples": config.bootstrap_samples,
        "eligible_to_freeze": eligible_to_freeze,
        "stability_threshold": config.stability_threshold,
        "max_failed_bootstrap_fraction": config.max_failed_bootstrap_fraction,
        "source_variable": source,
        "mechanism_variable": _MECHANISM,
        "outcome_variable": outcome,
    }
    if output_dir.exists():
        if (output_dir / "artifact-manifest.json").exists():
            raise ValueError("discovery-v2 bootstrap output is already closed")
        if _read_json(output_dir / "run-config.json") != run_config:
            raise ValueError("discovery-v2 bootstrap resume inputs failed validation")
    else:
        output_dir.mkdir(parents=True, exist_ok=False)
        (output_dir / "replicates").mkdir()
        _write_json(output_dir / "run-config.json", run_config)
        _write_json(output_dir / "command.json", {"argv": list(command_argv)})
        _write_json(output_dir / "environment.json", _environment())
    active_runner = SpawnedFCIRunner() if runner is None else runner
    successful: dict[int, PAGRecord] = {}
    failures: dict[int, str] = {}
    support_numerator = 0
    for replicate_index in range(planned_replicates):
        draw, matrix = _draw(
            blocks=blocks,
            provenance=provenance,
            replicate_index=replicate_index,
            variable_count=len(table.variables),
        )
        replicate_dir = output_dir / "replicates" / f"replicate-{replicate_index:04d}"
        if replicate_dir.exists():
            restored = _closed_replicate(replicate_dir, draw)
            if isinstance(restored, PAGRecord):
                checked = _validated_pag(
                    restored,
                    table=table,
                    knowledge=knowledge,
                    config=config,
                )
                successful[replicate_index] = checked
                candidate = _reference_path(checked, source=source, outcome=outcome)
                if candidate is not None and _path_matches(reference_path, candidate):
                    support_numerator += 1
            else:
                failures[replicate_index] = restored
            continue
        replicate_dir.mkdir()
        _write_json(replicate_dir / "draw.json", draw)
        try:
            pag = active_runner.run(matrix, table, knowledge, config, PAGRunKind.JCI_RAW)
            checked = _validated_pag(pag, table=table, knowledge=knowledge, config=config)
            _write_json(replicate_dir / "pag.json", checked.model_dump(mode="json"))
            successful[replicate_index] = checked
            candidate = _reference_path(checked, source=source, outcome=outcome)
            if candidate is not None and _path_matches(reference_path, candidate):
                support_numerator += 1
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as error:  # noqa: BLE001 - preserve a bounded failure artifact.
            reason = _failure_reason(error)
            _write_json(
                replicate_dir / "failure.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "replicate_index": replicate_index,
                    "reason_code": reason,
                },
            )
            failures[replicate_index] = reason
        _manifest(replicate_dir)
        print(
            f"BOOTSTRAP_PROGRESS completed={replicate_index + 1} "
            f"successful={len(successful)} failed={len(failures)} "
            f"supported={support_numerator} pending={planned_replicates - replicate_index - 1}",
            flush=True,
        )
    support = {
        "schema_version": _SCHEMA_VERSION,
        "path": reference_path.model_dump(mode="json"),
        "support_numerator": support_numerator,
        "support_denominator": planned_replicates,
        "support_fraction": support_numerator / planned_replicates,
    }
    write_jsonl(output_dir / "path-support.jsonl", [support])
    max_failures = int(config.max_failed_bootstrap_fraction * planned_replicates)
    stable = support_numerator >= config.stability_threshold * planned_replicates
    hypotheses = []
    if eligible_to_freeze and stable and len(failures) <= max_failures:
        semantic = {
            "schema_version": _SCHEMA_VERSION,
            "model_id": table.model_id,
            "scope_id": table.scope_id,
            "target_feature_id": "arm.target_patch_vs_noop_rewrite",
            "source_variable_id": source,
            "mechanism_variable_id": _MECHANISM,
            "outcome_variable_id": outcome,
            "path": support["path"],
            "support_numerator": support_numerator,
            "support_denominator": planned_replicates,
            "rank": 1,
            "expected_direction": "two_sided",
            "reference_pag_id": reference_pag.pag_id,
            "table_sha256": table.table_sha256,
            "independent_validation_required": True,
        }
        digest = canonical_sha256(semantic)
        hypotheses.append(
            {**semantic, "hypothesis_id": f"hypothesis_{digest}", "hypothesis_sha256": digest}
        )
    write_jsonl(output_dir / "frozen-hypotheses.jsonl", hypotheses)
    terminal_reason = None
    if eligible_to_freeze and len(failures) > max_failures:
        terminal_reason = "too_many_failed_bootstraps"
    elif eligible_to_freeze and not hypotheses:
        terminal_reason = "no_stable_hypothesis"
    failure_rows = []
    if terminal_reason is not None:
        failure_rows.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "model_id": table.model_id,
                "scope_id": table.scope_id,
                "reason_code": terminal_reason,
                "reference_pag_id": reference_pag.pag_id,
                "successful_replicates": len(successful),
                "failed_replicates": len(failures),
                "support_numerator": support_numerator,
                "support_denominator": planned_replicates,
            }
        )
    write_jsonl(output_dir / "discovery-failures.jsonl", failure_rows)
    status = "DISCOVERY_V2_BOOTSTRAP_PILOT_COMPLETE"
    if eligible_to_freeze:
        status = (
            "DISCOVERY_V2_BOOTSTRAP_COMPLETE"
            if len(failures) <= max_failures
            else "DISCOVERY_V2_BOOTSTRAP_FAILED"
        )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": status,
        "model_id": table.model_id,
        "view_id": view_id,
        "planned_replicates": planned_replicates,
        "successful_replicates": len(successful),
        "failed_replicates": len(failures),
        "pending_replicates": 0,
        "failure_counts": dict(sorted(Counter(failures.values()).items())),
        "maximum_allowed_failures": max_failures,
        "reference_candidate_paths": 1,
        "stable_candidate_paths": int(stable),
        "support_numerator": support_numerator,
        "support_denominator": planned_replicates,
        "support_fraction": support_numerator / planned_replicates,
        "frozen_hypotheses": len(hypotheses),
        "terminal_reason": terminal_reason,
        "scientific_claim_allowed": False,
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


__all__ = ["run_randomized_discovery_v2_bootstrap"]
