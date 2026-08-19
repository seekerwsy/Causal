"""Task-block stability analysis for the frozen functional discovery edge."""

from __future__ import annotations

import hashlib
from collections import Counter
from pathlib import Path

import numpy as np

from secaware.causal.paths import edge_allows_possible_direction, endpoint_marks_compatible
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner
from secaware.experiments.held_out_policy_analysis import _verify_directory_manifest
from secaware.exploratory.randomized_discovery_bootstrap import (
    _closed_replicate,
    _environment,
    _failure_reason,
    _manifest,
    _validated_pag,
    _write_json,
)
from secaware.exploratory.randomized_discovery_v2_fci import _base_background, _config, _read_json
from secaware.exploratory.randomized_discovery_v3_functional_fci import (
    _POLICY as _REFERENCE_POLICY,
)
from secaware.exploratory.randomized_discovery_v3_functional_fci import (
    _table_and_matrix,
    _validated_analysis,
)
from secaware.io.jsonl import write_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.randomness import RNG_VERSION, DeterministicRNG
from secaware.schema.causal import PAGEdgeRecord, PAGRecord, PAGRunKind

_SCHEMA_VERSION = "1.0"
_POLICY = "five-cwe-randomized-discovery-v3-functional-edge-bootstrap-v1"
_MODEL = "phi-4-14b"
_VIEW = "full_jci_functional"
_SOURCE = "z.target_mechanism_realized"
_TARGET = "y.discovery_functional"


def _canonical(value: object) -> bytes:
    import json

    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _edge(pag: PAGRecord) -> PAGEdgeRecord | None:
    for edge in pag.edges:
        if {edge.left, edge.right} == {_SOURCE, _TARGET}:
            return edge
    return None


def _edge_matches(reference: PAGEdgeRecord, candidate: PAGEdgeRecord) -> bool:
    reference_marks = reference.marks_from(_SOURCE, _TARGET)
    candidate_marks = candidate.marks_from(_SOURCE, _TARGET)
    return edge_allows_possible_direction(candidate, _SOURCE, _TARGET) and all(
        endpoint_marks_compatible(reference_mark, candidate_mark)
        for reference_mark, candidate_mark in zip(reference_marks, candidate_marks, strict=True)
    )


def _validated_bootstrap(path: Path) -> dict[str, object]:
    config = _read_json(path)
    expected = {
        "schema_version": "1.0",
        "bootstrap_id": "five_cwe_randomized_discovery_v3_bootstrap_phi_functional_edge_v1",
        "status": "FROZEN_AFTER_REFERENCE_EDGE_BEFORE_BOOTSTRAP",
        "model_id": _MODEL,
        "view_id": _VIEW,
        "source_variable": _SOURCE,
        "target_variable": _TARGET,
        "global_seed": 2026081922,
        "bootstrap_samples": 200,
        "bootstrap_unit": "complete_task_block",
        "stability_threshold": 0.8,
        "max_failed_bootstrap_fraction": 0.1,
        "interpretation": "mechanism_function_coupling_not_target_patch_mediation",
        "independent_validation_required": True,
        "scientific_claim_allowed": False,
    }
    if config != expected:
        raise ValueError("discovery-v3 functional bootstrap config failed validation")
    return config


def _draw(
    *,
    blocks: tuple[tuple[str, tuple[dict[str, object], ...]], ...],
    provenance: dict[str, object],
    replicate_index: int,
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
    if matrix.shape != (372, 3):
        raise ValueError("discovery-v3 functional bootstrap draw failed validation")
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


def run_randomized_discovery_v3_functional_bootstrap(
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
    table_manifest_sha256 = _verify_directory_manifest(table_dir)
    reference_manifest_sha256 = _verify_directory_manifest(reference_dir)
    analysis = _validated_analysis(analysis_config_path)
    bootstrap = _validated_bootstrap(bootstrap_config_path)
    reference_report = _read_json(reference_dir / "report.json")
    if (
        reference_report.get("status") != "DISCOVERY_V3_FUNCTIONAL_REFERENCE_FCI_COMPLETE"
        or reference_report.get("model_id") != _MODEL
        or reference_report.get("view_id") != _VIEW
        or reference_report.get("independent_tasks") != 93
    ):
        raise ValueError("discovery-v3 functional reference failed validation")
    matrix_path = table_dir / "matrix-phi14b-full_jci_functional.json"
    payload = _read_json(matrix_path)
    producer_sha256 = canonical_sha256(
        {
            "policy": _REFERENCE_POLICY,
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "table_manifest_sha256": table_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
        }
    )
    table, full_matrix, bindings = _table_and_matrix(payload, producer_sha256=producer_sha256)
    stored_table = type(table).model_validate(_read_json(reference_dir / "causal-table.json"))
    knowledge = _base_background(table)
    stored_knowledge = type(knowledge).model_validate(
        _read_json(reference_dir / "base-background-knowledge.json")
    )
    reference_pag = PAGRecord.model_validate(_read_json(reference_dir / "raw-pag.json"))
    reference_edge = _edge(reference_pag)
    config = _config(analysis)
    if (
        table != stored_table
        or knowledge != stored_knowledge
        or full_matrix.shape != (372, 3)
        or reference_pag.run_kind is not PAGRunKind.JCI_RAW
        or reference_edge is None
        or not edge_allows_possible_direction(reference_edge, _SOURCE, _TARGET)
        or config.bootstrap_samples != bootstrap["bootstrap_samples"]
        or config.stability_threshold != bootstrap["stability_threshold"]
        or config.max_failed_bootstrap_fraction != bootstrap["max_failed_bootstrap_fraction"]
    ):
        raise ValueError("discovery-v3 functional bootstrap inputs failed validation")
    arm_index = tuple(item.variable_id for item in table.variables).index("c.arm")
    grouped: dict[str, list[dict[str, object]]] = {}
    for binding in bindings:
        grouped.setdefault(str(binding["task_id"]), []).append(binding)
    blocks = []
    for task_id in sorted(grouped):
        block = tuple(sorted(grouped[task_id], key=lambda item: item["values"][arm_index]))
        if tuple(item["values"][arm_index] for item in block) != (0, 1, 2, 3):
            raise ValueError("discovery-v3 functional task block failed validation")
        blocks.append((task_id, block))
    if len(blocks) != 93:
        raise ValueError("discovery-v3 functional task population failed validation")
    sampling_frame_sha256 = canonical_sha256(
        {
            "policy": _POLICY,
            "model_id": _MODEL,
            "view_id": _VIEW,
            "blocks": [
                {
                    "task_id": task_id,
                    "assignments": [
                        {"assignment_id": item["assignment_id"], "arm": item["values"][arm_index]}
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
        "background_knowledge_sha256": knowledge.knowledge_sha256,
        "sampling_frame_sha256": sampling_frame_sha256,
        "global_seed": bootstrap["global_seed"],
        "rng_version": RNG_VERSION,
    }
    if engineering_replicates is None:
        planned = config.bootstrap_samples
        eligible_to_freeze = True
    elif type(engineering_replicates) is int and 1 <= engineering_replicates <= 10:
        planned = engineering_replicates
        eligible_to_freeze = False
    else:
        raise ValueError("discovery-v3 functional engineering bound failed validation")
    run_config = {
        **provenance,
        "planned_replicates": planned,
        "configured_bootstrap_samples": config.bootstrap_samples,
        "eligible_to_freeze": eligible_to_freeze,
        "stability_threshold": config.stability_threshold,
        "max_failed_bootstrap_fraction": config.max_failed_bootstrap_fraction,
        "source_variable": _SOURCE,
        "target_variable": _TARGET,
        "interpretation": bootstrap["interpretation"],
    }
    if output_dir.exists():
        if (output_dir / "artifact-manifest.json").exists():
            raise ValueError("discovery-v3 functional bootstrap output is closed")
        if _read_json(output_dir / "run-config.json") != run_config:
            raise ValueError("discovery-v3 functional bootstrap resume failed validation")
    else:
        output_dir.mkdir(parents=True, exist_ok=False)
        (output_dir / "replicates").mkdir()
        _write_json(output_dir / "run-config.json", run_config)
        _write_json(output_dir / "command.json", {"argv": list(command_argv)})
        _write_json(output_dir / "environment.json", _environment())
    active_runner = SpawnedFCIRunner() if runner is None else runner
    successful: dict[int, PAGRecord] = {}
    failures: dict[int, str] = {}
    supported = 0
    for replicate_index in range(planned):
        draw, matrix = _draw(
            blocks=tuple(blocks),
            provenance=provenance,
            replicate_index=replicate_index,
        )
        replicate_dir = output_dir / "replicates" / f"replicate-{replicate_index:04d}"
        if replicate_dir.exists():
            restored = _closed_replicate(replicate_dir, draw)
            if isinstance(restored, PAGRecord):
                pag = _validated_pag(restored, table=table, knowledge=knowledge, config=config)
                successful[replicate_index] = pag
                candidate = _edge(pag)
                if candidate is not None and _edge_matches(reference_edge, candidate):
                    supported += 1
            else:
                failures[replicate_index] = restored
            continue
        replicate_dir.mkdir()
        _write_json(replicate_dir / "draw.json", draw)
        try:
            pag = active_runner.run(matrix, table, knowledge, config, PAGRunKind.JCI_RAW)
            pag = _validated_pag(pag, table=table, knowledge=knowledge, config=config)
            _write_json(replicate_dir / "pag.json", pag.model_dump(mode="json"))
            successful[replicate_index] = pag
            candidate = _edge(pag)
            if candidate is not None and _edge_matches(reference_edge, candidate):
                supported += 1
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as error:  # noqa: BLE001 - preserve bounded failure artifacts.
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
            f"supported={supported} pending={planned - replicate_index - 1}",
            flush=True,
        )
    support = {
        "schema_version": _SCHEMA_VERSION,
        "source_variable": _SOURCE,
        "target_variable": _TARGET,
        "reference_marks": [item.value for item in reference_edge.marks_from(_SOURCE, _TARGET)],
        "support_numerator": supported,
        "support_denominator": planned,
        "support_fraction": supported / planned,
    }
    write_jsonl(output_dir / "edge-support.jsonl", [support])
    max_failures = int(config.max_failed_bootstrap_fraction * planned)
    stable = supported >= config.stability_threshold * planned
    hypotheses = []
    if eligible_to_freeze and stable and len(failures) <= max_failures:
        semantic = {
            "schema_version": _SCHEMA_VERSION,
            "model_id": _MODEL,
            "scope_id": table.scope_id,
            "source_variable_id": _SOURCE,
            "target_variable_id": _TARGET,
            "support_numerator": supported,
            "support_denominator": planned,
            "reference_pag_id": reference_pag.pag_id,
            "table_sha256": table.table_sha256,
            "interpretation": bootstrap["interpretation"],
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
    write_jsonl(
        output_dir / "discovery-failures.jsonl",
        []
        if terminal_reason is None
        else [
            {
                "schema_version": _SCHEMA_VERSION,
                "model_id": _MODEL,
                "reason_code": terminal_reason,
                "support_numerator": supported,
                "support_denominator": planned,
            }
        ],
    )
    status = "DISCOVERY_V3_FUNCTIONAL_BOOTSTRAP_PILOT_COMPLETE"
    if eligible_to_freeze:
        status = (
            "DISCOVERY_V3_FUNCTIONAL_BOOTSTRAP_COMPLETE"
            if len(failures) <= max_failures
            else "DISCOVERY_V3_FUNCTIONAL_BOOTSTRAP_FAILED"
        )
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": status,
        "model_id": _MODEL,
        "view_id": _VIEW,
        "planned_replicates": planned,
        "successful_replicates": len(successful),
        "failed_replicates": len(failures),
        "pending_replicates": 0,
        "failure_counts": dict(sorted(Counter(failures.values()).items())),
        "support_numerator": supported,
        "support_denominator": planned,
        "support_fraction": supported / planned,
        "stable_edges": int(stable),
        "frozen_hypotheses": len(hypotheses),
        "terminal_reason": terminal_reason,
        "scientific_claim_allowed": False,
        "independent_validation_required": True,
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


__all__ = ["run_randomized_discovery_v3_functional_bootstrap"]
