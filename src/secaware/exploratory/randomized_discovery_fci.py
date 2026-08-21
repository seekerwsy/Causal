"""Reference raw/JCI FCI for the frozen pooled randomized-discovery table."""

from __future__ import annotations

from datetime import UTC, datetime
import hashlib
import json
import os
import platform
from pathlib import Path
import socket
import sys
from typing import Any

import numpy as np
from pydantic import BaseModel

from secaware.causal.background import validate_pag_against_background
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import FCIDiscoveryConfig
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner
from secaware.io.jsonl import read_jsonl, write_jsonl
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    CausalVariableSpec,
    JCIBackgroundKnowledgeRecord,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
    VariableRole,
    jci_row_id_from_content,
)


_SCHEMA_VERSION = "1.0"
_POLICY = "five-cwe-randomized-discovery-reference-fci-v1"
_SCOPE = "scope.five_cwe_policy"
_POOLED_CWE = "CWE-POOLED"
_EXTERNAL_TO_INTERNAL = {
    "w_cwe_scope": "w.cwe_scope",
    "c_discovery_arm": "c.arm",
    "x_operation_specific_security_requirement": ("x.operation_specific_security_requirement"),
    "x_generic_security_reminder": "x.generic_security_reminder",
    "p_length_matched_placebo": "p.length_matched_placebo",
    "y_cwe_secure": "y.cwe_secure",
    "y_secure_functional": "y.secure_functional",
}
_VARIABLE_IDS = tuple(sorted(_EXTERNAL_TO_INTERNAL.values()))


def _canonical(value: object) -> bytes:
    return json.dumps(
        _json_value(value),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _json_value(value: object) -> object:
    if isinstance(value, BaseModel):
        return value.model_dump(mode="json", warnings=False)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    return value


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("randomized discovery FCI JSON object failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _verify_closed_dir(root: Path) -> str:
    manifest_path = root / "artifact-manifest.json"
    manifest = _read_json(manifest_path)
    entries = manifest.get("files")
    if manifest.get("schema_version") != _SCHEMA_VERSION or type(entries) is not list:
        raise ValueError("randomized discovery FCI input manifest failed validation")
    expected: set[str] = set()
    for entry in entries:
        if type(entry) is not dict or type(entry.get("path")) is not str:
            raise ValueError("randomized discovery FCI input manifest failed validation")
        relative = Path(str(entry["path"]))
        path = (root / relative).resolve()
        path.relative_to(root.resolve())
        normalized = relative.as_posix()
        if (
            relative.is_absolute()
            or normalized != entry["path"]
            or normalized in expected
            or not path.is_file()
            or sha256_file(path) != entry.get("sha256")
        ):
            raise ValueError("randomized discovery FCI input manifest failed validation")
        expected.add(normalized)
    actual = {
        path.relative_to(root).as_posix()
        for path in root.rglob("*")
        if path.is_file() and path != manifest_path
    }
    if actual != expected:
        raise ValueError("randomized discovery FCI input manifest closure failed validation")
    return sha256_file(manifest_path)


def _config(analysis: dict[str, Any]) -> FCIDiscoveryConfig:
    frozen = analysis.get("fci")
    if type(frozen) is not dict:
        raise ValueError("randomized discovery FCI configuration failed validation")
    return FCIDiscoveryConfig(
        backend=frozen.get("minimum_backend"),
        backend_version=frozen.get("backend_version"),
        ci_test=frozen.get("ci_test"),
        alpha=frozen.get("alpha"),
        depth=frozen.get("depth"),
        max_path_length=frozen.get("max_path_length"),
        bootstrap_samples=frozen.get("bootstrap_samples"),
        stability_threshold=frozen.get("stability_threshold"),
        max_failed_bootstrap_fraction=frozen.get("max_failed_bootstrap_fraction"),
        min_independent_tasks=20,
        max_variables=64,
        max_rows=100_000,
        max_candidate_paths=512,
        timeout_seconds=120.0,
    )


def _variables(
    matrix_payload: dict[str, Any], context_producer_sha256: str
) -> tuple[CausalVariableSpec, ...]:
    category_orders = matrix_payload.get("category_orders")
    if type(category_orders) is not dict:
        raise ValueError("randomized discovery FCI categories failed validation")
    binary = category_orders.get("binary")
    cwes = category_orders.get("w_cwe_scope")
    arms = category_orders.get("c_discovery_arm")
    if (
        type(binary) is not list
        or len(binary) != 2
        or type(cwes) is not list
        or len(cwes) != 5
        or type(arms) is not list
        or len(arms) != 4
    ):
        raise ValueError("randomized discovery FCI categories failed validation")
    if (
        tuple(binary) != ("absent_or_not_success", "present_or_success")
        or tuple(cwes) != declaration_by_id("w.cwe_scope").states
        or tuple(arms)
        != (
            "target_patch",
            "noop_rewrite",
            "length_matched_placebo",
            "generic_security_reminder",
        )
    ):
        raise ValueError("randomized discovery FCI categories failed validation")
    variables: list[CausalVariableSpec] = []
    for variable_id in _VARIABLE_IDS:
        if variable_id == "c.arm":
            variables.append(
                CausalVariableSpec(
                    schema_version=_SCHEMA_VERSION,
                    variable_id=variable_id,
                    role=VariableRole.C,
                    states=tuple(arms),
                    source_query_id="assignment.arm_role.v1",
                    scope_id=_SCOPE,
                    temporal_tier=0,
                    adjacency_type="jci_context",
                    producer_sha256=context_producer_sha256,
                )
            )
            continue
        declaration = declaration_by_id(variable_id)
        variables.append(
            CausalVariableSpec(
                schema_version=_SCHEMA_VERSION,
                variable_id=declaration.variable_id,
                role=declaration.role,
                states=declaration.states,
                source_query_id=declaration.query_id,
                scope_id=_SCOPE,
                temporal_tier=declaration.tier,
                adjacency_type=declaration.adjacency_type,
                producer_sha256=declaration_sha256(declaration),
            )
        )
    return tuple(variables)


def _table_and_matrix(
    rows: list[dict[str, Any]],
    matrix_payload: dict[str, Any],
    *,
    model_id: str,
    producer_sha256: str,
) -> tuple[CausalTableRecord, np.ndarray, tuple[dict[str, object], ...]]:
    variables = _variables(matrix_payload, producer_sha256)
    variable_ids = tuple(item.variable_id for item in variables)
    external_by_internal = {
        internal: external for external, internal in _EXTERNAL_TO_INTERNAL.items()
    }
    observations: list[tuple[str, str, str, str, str, str, str, tuple[int, ...]]] = []
    bindings: list[dict[str, object]] = []
    task_ids: set[str] = set()
    for row in rows:
        values_payload = row.get("values")
        if type(values_payload) is not dict or row.get("model_id") != model_id:
            raise ValueError("randomized discovery FCI row failed validation")
        values = tuple(int(values_payload[external_by_internal[item]]) for item in variable_ids)
        coordinates = (
            str(row["assignment_id"]),
            str(row["task_id"]),
            str(row["target_spec_id"]),
            str(row["target_instance_id"]),
            str(row["arm_protocol_id"]),
            str(row["protocol_instance_id"]),
        )
        row_id = jci_row_id_from_content(
            assignment_id=coordinates[0],
            task_id=coordinates[1],
            target_spec_id=coordinates[2],
            target_instance_id=coordinates[3],
            arm_protocol_id=coordinates[4],
            protocol_instance_id=coordinates[5],
            values=values,
        )
        observations.append((row_id, *coordinates, values))
        bindings.append(
            {
                "schema_version": _SCHEMA_VERSION,
                "row_id": row_id,
                "assignment_id": coordinates[0],
                "task_id": coordinates[1],
                "values": values,
            }
        )
        task_ids.add(coordinates[1])
    table = CausalTableRecord.from_jci_content(
        scope_id=_SCOPE,
        cwe=_POOLED_CWE,
        model_id=model_id,
        variables=variables,
        independent_task_count=len(task_ids),
        observation_payload=observations,
    )
    ordered_bindings = tuple(sorted(bindings, key=lambda item: str(item["assignment_id"])))
    matrix = np.asarray(tuple(item["values"] for item in ordered_bindings), dtype=np.int64)
    if matrix.shape != (len(rows), len(variables)) or not matrix.flags.c_contiguous:
        raise ValueError("randomized discovery FCI matrix failed validation")
    matrix.flags.writeable = False
    return table, matrix, ordered_bindings


def _base_background(table: CausalTableRecord) -> BackgroundKnowledgeRecord:
    tiered = tuple(item for item in table.variables if item.variable_id != "c.arm")
    tiers = tuple((item.variable_id, item.temporal_tier) for item in tiered)
    forbidden = tuple(
        sorted(
            (later.variable_id, earlier.variable_id)
            for later in tiered
            for earlier in tiered
            if later.temporal_tier > earlier.temporal_tier
        )
    )
    return BackgroundKnowledgeRecord.from_content(
        table_id=table.table_id,
        variable_ids=tuple(item.variable_id for item in table.variables),
        tiers=tiers,
        unconstrained_variable_ids=("c.arm",),
        forbidden_directions=forbidden,
        forbidden_adjacencies=(),
        required_directions=(),
    )


def _orientation_delta(raw: PAGRecord, constrained: PAGRecord) -> tuple[dict[str, object], ...]:
    def by_pair(pag: PAGRecord) -> dict[tuple[str, str], PAGEdgeRecord]:
        return {(item.left, item.right): item for item in pag.edges}

    raw_edges = by_pair(raw)
    constrained_edges = by_pair(constrained)
    return tuple(
        {
            "left": pair[0],
            "right": pair[1],
            "raw": (
                None
                if pair not in raw_edges
                else [raw_edges[pair].left_mark.value, raw_edges[pair].right_mark.value]
            ),
            "jci_constrained": (
                None
                if pair not in constrained_edges
                else [
                    constrained_edges[pair].left_mark.value,
                    constrained_edges[pair].right_mark.value,
                ]
            ),
        }
        for pair in sorted(set(raw_edges) | set(constrained_edges))
        if raw_edges.get(pair) != constrained_edges.get(pair)
    )


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "python_executable": sys.executable,
        "working_directory": os.getcwd(),
    }


def run_randomized_discovery_reference_fci(
    *,
    assembly_dir: Path,
    analysis_config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
    runner: FCIRunner | None = None,
) -> dict[str, object]:
    """Run the two reference PAGs before any task-cluster bootstrap expansion."""

    assembly_dir = assembly_dir.resolve()
    analysis_config_path = analysis_config_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists() or not assembly_dir.is_dir():
        raise ValueError("randomized discovery FCI path failed validation")
    assembly_manifest_sha256 = _verify_closed_dir(assembly_dir)
    analysis = _read_json(analysis_config_path)
    summary = _read_json(assembly_dir / "summary.json")
    matrix_payload = _read_json(assembly_dir / "categorical-matrix.json")
    rows = read_jsonl(assembly_dir / "analysis-rows.jsonl", required=True, allow_empty=False)
    model_id = str(summary.get("model_id"))
    if (
        analysis.get("status") != "FROZEN_BEFORE_DISCOVERY_OUTCOMES"
        or model_id not in analysis.get("model_strata", [])
        or summary.get("rows") != 204
        or summary.get("independent_tasks") != 51
        or summary.get("post_randomization_rows_dropped") != 0
        or len(rows) != 204
    ):
        raise ValueError("randomized discovery FCI frozen population failed validation")
    config = _config(analysis)
    producer_sha256 = canonical_sha256(
        {
            "policy": _POLICY,
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "assembly_manifest_sha256": assembly_manifest_sha256,
        }
    )
    table, matrix, bindings = _table_and_matrix(
        rows,
        matrix_payload,
        model_id=model_id,
        producer_sha256=producer_sha256,
    )
    base = _base_background(table)
    jci = JCIBackgroundKnowledgeRecord.from_base(
        base,
        assumption_ids=("jci.randomized_context_exogeneity.v1",),
        added_forbidden_directions=tuple(
            sorted(
                (item.variable_id, "c.arm")
                for item in table.variables
                if item.variable_id != "c.arm"
            )
        ),
    )
    active_runner = SpawnedFCIRunner() if runner is None else runner
    raw_pag = active_runner.run(matrix, table, base, config, PAGRunKind.JCI_RAW)
    constrained_pag = active_runner.run(
        matrix,
        table,
        jci.materialized_background_knowledge,
        config,
        PAGRunKind.JCI_CONSTRAINED,
    )
    validate_pag_against_background(raw_pag, base)
    validate_pag_against_background(constrained_pag, jci.materialized_background_knowledge)
    delta = _orientation_delta(raw_pag, constrained_pag)

    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "causal-table.json", table)
    write_jsonl(output_dir / "row-bindings.jsonl", bindings)
    _write_json(output_dir / "base-background-knowledge.json", base)
    _write_json(output_dir / "jci-background-knowledge.json", jci)
    _write_json(output_dir / "raw-pag.json", raw_pag)
    _write_json(output_dir / "jci-constrained-pag.json", constrained_pag)
    write_jsonl(output_dir / "jci-orientation-delta.jsonl", delta)
    _write_json(
        output_dir / "provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "policy": _POLICY,
            "assembly_directory": str(assembly_dir),
            "assembly_manifest_sha256": assembly_manifest_sha256,
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "matrix_sha256": hashlib.sha256(matrix.tobytes(order="C")).hexdigest(),
            "matrix_shape": list(matrix.shape),
            "typed_adjacency_policy": "pooled_policy_all_declared_types_allowed_v1",
            "typed_forbidden_adjacencies": [],
            "candidate_path_source": "raw_pag",
            "jci_role": "secondary_orientation_sensitivity",
        },
    )
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "RANDOMIZED_DISCOVERY_REFERENCE_FCI_COMPLETE",
        "model_id": model_id,
        "rows": table.row_count,
        "independent_tasks": table.independent_task_count,
        "raw_pag_edges": len(raw_pag.edges),
        "jci_constrained_pag_edges": len(constrained_pag.edges),
        "jci_orientation_deltas": len(delta),
        "bootstrap_runs": 0,
        "hypotheses_frozen": 0,
        "next_stage": "task_cluster_bootstrap",
    }
    _write_json(output_dir / "report.json", report)
    files = sorted(path for path in output_dir.rglob("*") if path.is_file())
    _write_json(
        output_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {
                    "path": path.relative_to(output_dir).as_posix(),
                    "sha256": sha256_file(path),
                }
                for path in files
            ],
        },
    )
    return report


__all__ = ["run_randomized_discovery_reference_fci"]
