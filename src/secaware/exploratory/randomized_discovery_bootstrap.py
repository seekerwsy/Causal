"""Four-arm task-cluster bootstrap for randomized exploratory discovery."""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
import hashlib
import json
import os
import platform
from pathlib import Path
import socket
import sys

import numpy as np

from secaware.causal.background import validate_pag_against_background
from secaware.causal.paths import edge_allows_possible_direction, endpoint_marks_compatible
from secaware.config import FCIDiscoveryConfig
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner
from secaware.errors import SecAwareError
from secaware.exploratory.randomized_discovery_fci import (
    _POLICY as _REFERENCE_POLICY,
    _config,
    _read_json,
    _table_and_matrix,
    _verify_closed_dir,
)
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.randomness import DeterministicRNG, RNG_VERSION
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
    PathPatternRecord,
)


_SCHEMA_VERSION = "1.0"
_POLICY = "five-cwe-randomized-discovery-task-block-bootstrap-v1"
_SOURCE = "x.operation_specific_security_requirement"
_OUTCOMES = ("y.secure_functional", "y.cwe_secure")
_EXCLUDED_INTERNAL = frozenset({"c.arm", *_OUTCOMES})


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "python_executable": sys.executable,
        "working_directory": os.getcwd(),
    }


def _manifest(root: Path) -> None:
    files = sorted(path for path in root.rglob("*") if path.is_file())
    _write_json(
        root / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.relative_to(root).as_posix(), "sha256": sha256_file(path)}
                for path in files
            ],
        },
    )


def _edges(pag: PAGRecord) -> dict[tuple[str, str], PAGEdgeRecord]:
    return {(item.left, item.right): item for item in pag.edges}


def _edge_for(
    edges: dict[tuple[str, str], PAGEdgeRecord], source: str, target: str
) -> PAGEdgeRecord:
    pair = (source, target) if source < target else (target, source)
    return edges[pair]


def enumerate_policy_paths(
    pag: PAGRecord,
    *,
    max_path_length: int,
    max_candidate_paths: int,
) -> tuple[PathPatternRecord, ...]:
    """Enumerate exact pooled-policy source-to-outcome paths, excluding JCI context."""

    checked = PAGRecord.model_validate(pag)
    if (
        _SOURCE not in checked.variable_ids
        or any(item not in checked.variable_ids for item in _OUTCOMES)
        or type(max_path_length) is not int
        or not 1 <= max_path_length <= 16
        or type(max_candidate_paths) is not int
        or not 1 <= max_candidate_paths <= 4096
    ):
        raise ValueError("randomized discovery path inputs failed validation")
    edges = _edges(checked)
    neighbors = {
        variable_id: tuple(
            sorted(
                right if left == variable_id else left
                for left, right in edges
                if left == variable_id or right == variable_id
            )
        )
        for variable_id in checked.variable_ids
    }
    candidates: list[PathPatternRecord] = []
    expansions = 0

    def walk(path: tuple[str, ...]) -> None:
        nonlocal expansions
        if len(path) - 1 >= max_path_length:
            return
        current = path[-1]
        for target in neighbors[current]:
            if target in path or target == "c.arm":
                continue
            edge = _edge_for(edges, current, target)
            if not edge_allows_possible_direction(edge, current, target):
                continue
            extended = (*path, target)
            if target in _OUTCOMES:
                marks = tuple(
                    _edge_for(edges, source, destination).marks_from(source, destination)
                    for source, destination in zip(extended[:-1], extended[1:], strict=True)
                )
                candidates.append(
                    PathPatternRecord.from_content(
                        variable_ids=extended,
                        endpoint_marks=marks,
                    )
                )
                if len(candidates) > max_candidate_paths:
                    raise ValueError("randomized discovery candidate path limit exceeded")
                continue
            if target not in _EXCLUDED_INTERNAL:
                expansions += 1
                if expansions > max_candidate_paths * max_path_length:
                    raise ValueError("randomized discovery path search limit exceeded")
                walk(extended)

    walk((_SOURCE,))
    unique = {(item.variable_ids, item.endpoint_marks): item for item in candidates}
    if len(unique) != len(candidates):
        raise ValueError("randomized discovery duplicate path failed validation")
    return tuple(
        sorted(
            unique.values(),
            key=lambda item: (
                item.variable_ids,
                tuple((left.value, right.value) for left, right in item.endpoint_marks),
            ),
        )
    )


def _path_matches(reference: PathPatternRecord, candidate: PathPatternRecord) -> bool:
    return reference.variable_ids == candidate.variable_ids and all(
        endpoint_marks_compatible(reference_mark, candidate_mark)
        for reference_pair, candidate_pair in zip(
            reference.endpoint_marks,
            candidate.endpoint_marks,
            strict=True,
        )
        for reference_mark, candidate_mark in zip(reference_pair, candidate_pair, strict=True)
    )


def _failure_reason(error: BaseException) -> str:
    if isinstance(error, SecAwareError):
        message = f"{error.stage}:{error.message}".casefold()
        if "timeout" in message or "timed out" in message:
            return "backend_timeout"
        if "background" in message:
            return "background_knowledge_violation"
        if "degenerate" in message or "g-square" in message:
            return "degenerate_gsq_support"
        if "worker failed validation" in message:
            return "backend_crash"
        return "invalid_backend_output"
    if isinstance(error, ValueError):
        return "invalid_backend_output"
    return "backend_crash"


def _validated_pag(
    pag: object,
    *,
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
) -> PAGRecord:
    checked = PAGRecord.model_validate(pag)
    if (
        checked.run_kind is not PAGRunKind.JCI_RAW
        or checked.table_id != table.table_id
        or checked.backend != config.backend
        or checked.backend_version != config.backend_version
        or checked.ci_test != config.ci_test
        or checked.config_sha256 != canonical_sha256(config.model_dump(mode="json"))
        or checked.background_knowledge_sha256 != knowledge.knowledge_sha256
        or checked.variable_ids != tuple(item.variable_id for item in table.variables)
    ):
        raise ValueError("randomized discovery bootstrap PAG failed validation")
    validate_pag_against_background(checked, knowledge)
    return checked


def _load_inputs(
    *,
    assembly_dir: Path,
    reference_dir: Path,
    analysis_config_path: Path,
    gate_a_config_path: Path,
) -> tuple[
    CausalTableRecord,
    BackgroundKnowledgeRecord,
    PAGRecord,
    FCIDiscoveryConfig,
    tuple[tuple[str, tuple[dict[str, object], ...]], ...],
    dict[str, object],
]:
    assembly_manifest_sha256 = _verify_closed_dir(assembly_dir)
    reference_manifest_sha256 = _verify_closed_dir(reference_dir)
    analysis = _read_json(analysis_config_path)
    gate_a = _read_json(gate_a_config_path)
    summary = _read_json(assembly_dir / "summary.json")
    matrix_payload = _read_json(assembly_dir / "categorical-matrix.json")
    rows = read_jsonl(assembly_dir / "analysis-rows.jsonl", required=True, allow_empty=False)
    model_id = str(summary.get("model_id"))
    producer_sha256 = canonical_sha256(
        {
            "policy": _REFERENCE_POLICY,
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "assembly_manifest_sha256": assembly_manifest_sha256,
        }
    )
    table, full_matrix, bindings = _table_and_matrix(
        rows,
        matrix_payload,
        model_id=model_id,
        producer_sha256=producer_sha256,
    )
    stored_table = CausalTableRecord.model_validate(_read_json(reference_dir / "causal-table.json"))
    knowledge = BackgroundKnowledgeRecord.model_validate(
        _read_json(reference_dir / "base-background-knowledge.json")
    )
    reference_pag = PAGRecord.model_validate(_read_json(reference_dir / "raw-pag.json"))
    config = _config(analysis)
    if (
        table != stored_table
        or reference_pag.run_kind is not PAGRunKind.JCI_RAW
        or reference_pag.table_id != table.table_id
        or knowledge.table_id != table.table_id
        or gate_a.get("model_id") != model_id
        or gate_a.get("global_seed") != 2026081821
        or gate_a.get("expected_discover_tasks") != 51
        or config.bootstrap_samples != 200
        or config.stability_threshold != 0.8
        or config.max_failed_bootstrap_fraction != 0.1
        or full_matrix.shape != (204, 7)
    ):
        raise ValueError("randomized discovery bootstrap frozen inputs failed validation")
    validate_pag_against_background(reference_pag, knowledge)
    arm_index = tuple(item.variable_id for item in table.variables).index("c.arm")
    grouped: dict[str, list[dict[str, object]]] = {}
    for binding in bindings:
        grouped.setdefault(str(binding["task_id"]), []).append(binding)
    blocks: list[tuple[str, tuple[dict[str, object], ...]]] = []
    for task_id in sorted(grouped):
        block = tuple(sorted(grouped[task_id], key=lambda item: item["values"][arm_index]))
        if len(block) != 4 or tuple(item["values"][arm_index] for item in block) != (0, 1, 2, 3):
            raise ValueError("randomized discovery four-arm block failed validation")
        blocks.append((task_id, block))
    if len(blocks) != 51:
        raise ValueError("randomized discovery task population failed validation")
    sampling_frame_sha256 = canonical_sha256(
        {
            "policy": _POLICY,
            "model_id": model_id,
            "pre_outcome_variable_ids": [
                item.variable_id
                for item in table.variables
                if not item.variable_id.startswith("y.")
            ],
            "blocks": [
                {
                    "task_id": task_id,
                    "assignments": [
                        {
                            "assignment_id": item["assignment_id"],
                            "pre_outcome_values": list(item["values"][:-2]),
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
        "assembly_manifest_sha256": assembly_manifest_sha256,
        "reference_manifest_sha256": reference_manifest_sha256,
        "analysis_config_sha256": sha256_file(analysis_config_path),
        "gate_a_config_sha256": sha256_file(gate_a_config_path),
        "table_sha256": table.table_sha256,
        "reference_pag_id": reference_pag.pag_id,
        "background_knowledge_sha256": knowledge.knowledge_sha256,
        "sampling_frame_sha256": sampling_frame_sha256,
        "global_seed": gate_a["global_seed"],
        "rng_version": RNG_VERSION,
        "candidate_path_source": "raw_pag",
        "jci_role": "secondary_orientation_sensitivity_only",
    }
    return table, knowledge, reference_pag, config, tuple(blocks), provenance


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
    selected = tuple(rng.choice(blocks) for _index in range(len(blocks)))
    matrix_rows: list[tuple[int, ...]] = []
    coordinates: list[dict[str, object]] = []
    for draw_index, (task_id, block) in enumerate(selected):
        for arm_index, item in enumerate(block):
            values = tuple(int(value) for value in item["values"])
            matrix_rows.append(values)
            coordinates.append(
                {
                    "draw_index": draw_index,
                    "arm_index": arm_index,
                    "task_id": task_id,
                    "assignment_id": item["assignment_id"],
                    "row_id": item["row_id"],
                }
            )
    matrix = np.asarray(matrix_rows, dtype=np.int64)
    if matrix.shape != (204, 7):
        raise ValueError("randomized discovery bootstrap matrix failed validation")
    matrix = np.array(matrix, dtype=np.int64, order="C", copy=True)
    matrix.flags.writeable = False
    draw: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "replicate_index": replicate_index,
        "rng_version": RNG_VERSION,
        "seed_material_sha256": hashlib.sha256(seed_material).hexdigest(),
        "sampled_task_ids": [task_id for task_id, _block in selected],
        "row_coordinates": coordinates,
        "matrix_sha256": hashlib.sha256(matrix.tobytes(order="C")).hexdigest(),
    }
    draw["draw_sha256"] = canonical_sha256(draw)
    return draw, matrix


def _closed_replicate(directory: Path, expected_draw: dict[str, object]) -> PAGRecord | str:
    _verify_closed_dir(directory)
    if _read_json(directory / "draw.json") != expected_draw:
        raise ValueError("randomized discovery saved draw failed validation")
    pag_path = directory / "pag.json"
    failure_path = directory / "failure.json"
    if pag_path.is_file() == failure_path.is_file():
        raise ValueError("randomized discovery replicate terminal state failed validation")
    if pag_path.is_file():
        return PAGRecord.model_validate(_read_json(pag_path))
    failure = _read_json(failure_path)
    return str(failure["reason_code"])


def run_randomized_discovery_bootstrap(
    *,
    assembly_dir: Path,
    reference_dir: Path,
    analysis_config_path: Path,
    gate_a_config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
    engineering_replicates: int | None = None,
    runner: FCIRunner | None = None,
) -> dict[str, object]:
    """Run or resume one immutable four-arm task-cluster bootstrap stratum."""

    assembly_dir = assembly_dir.resolve()
    reference_dir = reference_dir.resolve()
    analysis_config_path = analysis_config_path.resolve()
    gate_a_config_path = gate_a_config_path.resolve()
    output_dir = output_dir.resolve()
    table, knowledge, reference_pag, config, blocks, provenance = _load_inputs(
        assembly_dir=assembly_dir,
        reference_dir=reference_dir,
        analysis_config_path=analysis_config_path,
        gate_a_config_path=gate_a_config_path,
    )
    if engineering_replicates is None:
        planned_replicates = config.bootstrap_samples
        eligible_to_freeze = True
    else:
        if type(engineering_replicates) is not int or not 1 <= engineering_replicates <= 10:
            raise ValueError("randomized discovery engineering replicate bound failed validation")
        planned_replicates = engineering_replicates
        eligible_to_freeze = False
    run_config = {
        **provenance,
        "planned_replicates": planned_replicates,
        "configured_bootstrap_samples": config.bootstrap_samples,
        "eligible_to_freeze": eligible_to_freeze,
        "stability_threshold": config.stability_threshold,
        "max_failed_bootstrap_fraction": config.max_failed_bootstrap_fraction,
        "max_path_length": config.max_path_length,
        "max_candidate_paths": config.max_candidate_paths,
    }
    if output_dir.exists():
        if (output_dir / "artifact-manifest.json").exists():
            raise ValueError("randomized discovery bootstrap output is already closed")
        if _read_json(output_dir / "run-config.json") != run_config:
            raise ValueError("randomized discovery bootstrap resume inputs failed validation")
    else:
        output_dir.mkdir(parents=True, exist_ok=False)
        (output_dir / "replicates").mkdir()
        _write_json(output_dir / "run-config.json", run_config)
        _write_json(output_dir / "command.json", {"argv": list(command_argv)})
        _write_json(output_dir / "environment.json", _environment())

    reference_paths = enumerate_policy_paths(
        reference_pag,
        max_path_length=config.max_path_length,
        max_candidate_paths=config.max_candidate_paths,
    )
    active_runner = SpawnedFCIRunner() if runner is None else runner
    successful: dict[int, PAGRecord] = {}
    failures: dict[int, str] = {}
    for replicate_index in range(planned_replicates):
        draw, matrix = _draw(
            blocks=blocks,
            provenance=provenance,
            replicate_index=replicate_index,
        )
        replicate_dir = output_dir / "replicates" / f"replicate-{replicate_index:04d}"
        if replicate_dir.exists():
            restored = _closed_replicate(replicate_dir, draw)
            if isinstance(restored, PAGRecord):
                successful[replicate_index] = _validated_pag(
                    restored,
                    table=table,
                    knowledge=knowledge,
                    config=config,
                )
            else:
                failures[replicate_index] = restored
            continue
        replicate_dir.mkdir()
        _write_json(replicate_dir / "draw.json", draw)
        try:
            pag = active_runner.run(matrix, table, knowledge, config, PAGRunKind.JCI_RAW)
            checked = _validated_pag(
                pag,
                table=table,
                knowledge=knowledge,
                config=config,
            )
            _write_json(replicate_dir / "pag.json", checked.model_dump(mode="json"))
            successful[replicate_index] = checked
        except (KeyboardInterrupt, SystemExit):
            raise
        except BaseException as error:
            reason = _failure_reason(error)
            _write_json(
                replicate_dir / "failure.json",
                {
                    "schema_version": _SCHEMA_VERSION,
                    "replicate_index": replicate_index,
                    "reason_code": reason,
                    "detail_sha256": canonical_sha256(
                        {"stage": "randomized_discovery_bootstrap", "reason_code": reason}
                    ),
                },
            )
            failures[replicate_index] = reason
        _manifest(replicate_dir)
        print(
            f"BOOTSTRAP_PROGRESS completed={replicate_index + 1} "
            f"successful={len(successful)} failed={len(failures)} "
            f"pending={planned_replicates - replicate_index - 1}",
            flush=True,
        )

    supports: list[dict[str, object]] = []
    paths_by_replicate = {
        index: enumerate_policy_paths(
            pag,
            max_path_length=config.max_path_length,
            max_candidate_paths=config.max_candidate_paths,
        )
        for index, pag in successful.items()
    }
    for reference in reference_paths:
        numerator = sum(
            any(_path_matches(reference, candidate) for candidate in candidates)
            for candidates in paths_by_replicate.values()
        )
        supports.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "path": reference.model_dump(mode="json"),
                "support_numerator": numerator,
                "support_denominator": planned_replicates,
                "support_fraction": numerator / planned_replicates,
            }
        )
    write_jsonl(output_dir / "path-support.jsonl", supports)
    max_failures = int(config.max_failed_bootstrap_fraction * planned_replicates)
    stable = [
        item
        for item in supports
        if item["support_numerator"] >= config.stability_threshold * item["support_denominator"]
    ]
    ranked = sorted(
        stable,
        key=lambda item: (
            -float(item["support_fraction"]),
            _OUTCOMES.index(item["path"]["variable_ids"][-1]),
            len(item["path"]["variable_ids"]),
            item["path"]["path_id"],
        ),
    )[:3]
    hypotheses: list[dict[str, object]] = []
    if eligible_to_freeze and len(failures) <= max_failures:
        for rank, item in enumerate(ranked, start=1):
            semantic = {
                "schema_version": _SCHEMA_VERSION,
                "model_id": table.model_id,
                "scope_id": table.scope_id,
                "target_feature_id": "policy.operation_specific_security_requirement",
                "source_variable_id": _SOURCE,
                "outcome_variable_id": item["path"]["variable_ids"][-1],
                "path": item["path"],
                "support_numerator": item["support_numerator"],
                "support_denominator": item["support_denominator"],
                "rank": rank,
                "expected_direction": "two_sided",
                "reference_pag_id": reference_pag.pag_id,
                "table_sha256": table.table_sha256,
            }
            digest = canonical_sha256(semantic)
            hypotheses.append(
                {
                    **semantic,
                    "hypothesis_id": f"hypothesis_{digest}",
                    "hypothesis_sha256": digest,
                }
            )
    write_jsonl(output_dir / "frozen-hypotheses.jsonl", hypotheses)
    failure_counts = dict(sorted(Counter(failures.values()).items()))
    status = "RANDOMIZED_DISCOVERY_BOOTSTRAP_PILOT_COMPLETE"
    if eligible_to_freeze:
        status = (
            "RANDOMIZED_DISCOVERY_BOOTSTRAP_COMPLETE"
            if len(failures) <= max_failures
            else "RANDOMIZED_DISCOVERY_BOOTSTRAP_FAILED"
        )
    terminal_reason = None
    if eligible_to_freeze and len(failures) > max_failures:
        terminal_reason = "too_many_failed_bootstraps"
    elif eligible_to_freeze and not hypotheses:
        terminal_reason = "no_stable_hypothesis"
    discovery_failures: list[dict[str, object]] = []
    if terminal_reason is not None:
        failure_content: dict[str, object] = {
            "schema_version": _SCHEMA_VERSION,
            "model_id": table.model_id,
            "scope_id": table.scope_id,
            "reason_code": terminal_reason,
            "table_sha256": table.table_sha256,
            "reference_pag_id": reference_pag.pag_id,
            "successful_replicates": len(successful),
            "failed_replicates": len(failures),
            "reference_candidate_paths": len(reference_paths),
            "stable_candidate_paths": len(stable),
        }
        digest = canonical_sha256(failure_content)
        discovery_failures.append(
            {
                **failure_content,
                "failure_id": f"discovery_failure_{digest}",
                "failure_sha256": digest,
            }
        )
    write_jsonl(output_dir / "discovery-failures.jsonl", discovery_failures)
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": status,
        "model_id": table.model_id,
        "planned_replicates": planned_replicates,
        "successful_replicates": len(successful),
        "failed_replicates": len(failures),
        "pending_replicates": 0,
        "failure_counts": failure_counts,
        "maximum_allowed_failures": max_failures,
        "reference_candidate_paths": len(reference_paths),
        "stable_candidate_paths": len(stable),
        "frozen_hypotheses": len(hypotheses),
        "terminal_reason": terminal_reason,
        "candidate_path_source": "raw_pag",
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


__all__ = ["enumerate_policy_paths", "run_randomized_discovery_bootstrap"]
