from __future__ import annotations

import hashlib
import json
import os
import platform
import socket
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import numpy as np

from secaware.causal.background import validate_pag_against_background
from secaware.causal.paths import edge_allows_possible_direction
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import FCIDiscoveryConfig
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner
from secaware.experiments.held_out_policy_analysis import _verify_directory_manifest
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
_POLICY = "five-cwe-randomized-discovery-v2-reference-fci-v1"
_ANALYSIS_V1 = "five_cwe_randomized_discovery_v2_analysis_v1"
_ANALYSIS_V2 = "five_cwe_randomized_discovery_v2_nonredundant_jci_v1"
_MODELS = ("qwen2.5-coder-7b-instruct", "phi-4-14b")
_VIEWS = (
    "target_noop_security",
    "target_noop_joint",
    "full_jci_security",
    "full_jci_joint",
)
_SOURCE = "x.operation_specific_security_requirement"
_MECHANISM = "z.target_mechanism_realized"
_OUTCOME_BY_VIEW = {
    "target_noop_security": "y.discovery_cwe_secure",
    "target_noop_joint": "y.discovery_secure_functional",
    "full_jci_security": "y.discovery_cwe_secure",
    "full_jci_joint": "y.discovery_secure_functional",
}
_INTERNAL_VARIABLES_BY_VIEW = {
    "target_noop_security": (
        "w.cwe_scope",
        "c.arm",
        "x.operation_specific_security_requirement",
        "z.target_mechanism_realized",
        "y.discovery_cwe_secure",
    ),
    "target_noop_joint": (
        "w.cwe_scope",
        "c.arm",
        "x.operation_specific_security_requirement",
        "z.target_mechanism_realized",
        "y.discovery_secure_functional",
    ),
    "full_jci_security": (
        "w.cwe_scope",
        "c.arm",
        "x.operation_specific_security_requirement",
        "x.generic_security_reminder",
        "p.length_matched_placebo",
        "z.target_mechanism_realized",
        "y.discovery_cwe_secure",
    ),
    "full_jci_joint": (
        "w.cwe_scope",
        "c.arm",
        "x.operation_specific_security_requirement",
        "x.generic_security_reminder",
        "p.length_matched_placebo",
        "z.target_mechanism_realized",
        "y.discovery_secure_functional",
    ),
}
_TEMPORAL_TIERS = {
    "w.cwe_scope": 0,
    "x.operation_specific_security_requirement": 1,
    "x.generic_security_reminder": 1,
    "p.length_matched_placebo": 1,
    "z.target_mechanism_realized": 2,
    "y.discovery_cwe_secure": 3,
    "y.discovery_secure_functional": 3,
}
_NONREDUNDANT_PROJECTION_BY_VIEW = {
    "target_noop_security": (
        "w.cwe_scope",
        "c.arm",
        "z.target_mechanism_realized",
        "y.discovery_cwe_secure",
    ),
    "target_noop_joint": (
        "w.cwe_scope",
        "c.arm",
        "z.target_mechanism_realized",
        "y.discovery_secure_functional",
    ),
    "full_jci_security": (
        "w.cwe_scope",
        "c.arm",
        "z.target_mechanism_realized",
        "y.discovery_cwe_secure",
    ),
    "full_jci_joint": (
        "w.cwe_scope",
        "c.arm",
        "z.target_mechanism_realized",
        "y.discovery_secure_functional",
    ),
}


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
        default=lambda item: item.model_dump(mode="json", warnings=False),
    ).encode("utf-8")


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if type(value) is not dict:
        raise ValueError("discovery-v2 FCI JSON object failed validation")
    return value


def _write_json(path: Path, value: object) -> None:
    with path.open("xb") as handle:
        handle.write(_canonical(value) + b"\n")


def _write_jsonl(path: Path, rows: tuple[dict[str, object], ...]) -> None:
    with path.open("x", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(_canonical(row).decode("utf-8") + "\n")


def _environment() -> dict[str, object]:
    return {
        "captured_at_utc": datetime.now(UTC).isoformat(),
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "python": sys.version,
        "python_executable": sys.executable,
        "working_directory": os.getcwd(),
    }


def _config(analysis: dict[str, Any]) -> FCIDiscoveryConfig:
    frozen = analysis.get("fci")
    if type(frozen) is not dict:
        raise ValueError("discovery-v2 FCI config failed validation")
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


def _validated_analysis(path: Path) -> dict[str, Any]:
    analysis = _read_json(path)
    analysis_id = analysis.get("analysis_id")
    population = analysis.get("development_population", {})
    background = analysis.get("background_knowledge", {})
    fci = analysis.get("fci", {})
    candidate = analysis.get("candidate_freeze", {})
    if (
        analysis.get("schema_version") != _SCHEMA_VERSION
        or analysis_id not in {_ANALYSIS_V1, _ANALYSIS_V2}
        or analysis.get("model_strata") != list(_MODELS)
        or analysis.get("views", {}).get("primary") != "target_noop_security"
        or analysis.get("views", {}).get("secondary") != "target_noop_joint"
        or analysis.get("views", {}).get("sensitivities") != ["full_jci_security", "full_jci_joint"]
        or population.get("tasks_per_model") != 51
        or population.get("outcomes_previously_observed") is not True
        or population.get("scientific_confirmation_allowed") is not False
        or population.get("model_pooling") != "forbidden"
        or population.get("target_noop_context_policy") != "explicit_jci_arm_v2"
        or candidate.get("required_mechanism_variable") != _MECHANISM
        or candidate.get("outcome_by_view") != _OUTCOME_BY_VIEW
        or candidate.get("minimum_stability") != 0.8
        or candidate.get("confirmation_outcomes_may_select_or_rescue") is not False
        or background.get("temporal_tiers") != _TEMPORAL_TIERS
        or background.get("jci_context_variable") != "c.arm"
        or background.get("jci_assumption") != "jci.randomized_context_exogeneity.v1"
        or background.get("required_directions") != []
        or background.get("required_adjacencies") != []
        or fci.get("bootstrap_unit") != "complete_task_block"
        or analysis.get("independent_validation_required") is not True
    ):
        raise ValueError("discovery-v2 frozen analysis failed validation")
    if analysis_id == _ANALYSIS_V1:
        if (
            analysis.get("status") != "EXPLORATORY_METHOD_DEVELOPMENT_FROZEN_BEFORE_V2_FCI"
            or candidate.get("source_variable") != _SOURCE
            or analysis.get("variable_projection_by_view") is not None
        ):
            raise ValueError("discovery-v2 original analysis failed validation")
    elif (
        analysis.get("status")
        != "EXPLORATORY_METHOD_DEVELOPMENT_FROZEN_BEFORE_NONREDUNDANT_JCI_FCI"
        or candidate.get("source_variable") != "c.arm"
        or candidate.get("target_noop_estimand") != "target_patch_vs_noop_rewrite"
        or analysis.get("deterministic_redundancy_resolution", {}).get("excluded_variable")
        != _SOURCE
        or analysis.get("deterministic_redundancy_resolution", {}).get("selection_basis")
        != "structural_identifiability_not_observed_effect"
        or analysis.get("variable_projection_by_view")
        != {key: list(value) for key, value in _NONREDUNDANT_PROJECTION_BY_VIEW.items()}
    ):
        raise ValueError("discovery-v2 nonredundant analysis failed validation")
    _config(analysis)
    return analysis


def _variables(
    payload: dict[str, Any],
    producer_sha256: str,
    projected_internal_ids: tuple[str, ...] | None = None,
) -> tuple[CausalVariableSpec, ...]:
    internal_ids = (
        payload.get("internal_variable_ids")
        if projected_internal_ids is None
        else list(projected_internal_ids)
    )
    if type(internal_ids) is not list or not 4 <= len(internal_ids) <= 7:
        raise ValueError("discovery-v2 variable list failed validation")
    variables = []
    for variable_id in internal_ids:
        if variable_id == "c.arm":
            variables.append(
                CausalVariableSpec(
                    schema_version=_SCHEMA_VERSION,
                    variable_id="c.arm",
                    role=VariableRole.C,
                    states=(
                        "target_patch",
                        "noop_rewrite",
                        "length_matched_placebo",
                        "generic_security_reminder",
                    ),
                    source_query_id="assignment.arm_role.v1",
                    scope_id="scope.five_cwe_policy_mechanism_v2",
                    temporal_tier=0,
                    adjacency_type="jci_context",
                    producer_sha256=producer_sha256,
                )
            )
            continue
        declaration = declaration_by_id(str(variable_id))
        variables.append(
            CausalVariableSpec(
                schema_version=_SCHEMA_VERSION,
                variable_id=declaration.variable_id,
                role=declaration.role,
                states=declaration.states,
                source_query_id=declaration.query_id,
                scope_id="scope.five_cwe_policy_mechanism_v2",
                temporal_tier=declaration.tier,
                adjacency_type=declaration.adjacency_type,
                producer_sha256=declaration_sha256(declaration),
            )
        )
    checked = tuple(sorted(variables, key=lambda item: item.variable_id))
    if _MECHANISM not in {item.variable_id for item in checked} or len(checked) != len(
        {item.variable_id for item in checked}
    ):
        raise ValueError("discovery-v2 required variables failed validation")
    return checked


def _table_and_matrix(
    payload: dict[str, Any],
    *,
    producer_sha256: str,
    projected_internal_ids: tuple[str, ...] | None = None,
) -> tuple[CausalTableRecord, np.ndarray, tuple[dict[str, object], ...]]:
    view_id = str(payload.get("view_id"))
    model_id = str(payload.get("model_id"))
    rows = payload.get("rows")
    input_internal = payload.get("internal_variable_ids")
    if (
        view_id not in _VIEWS
        or model_id not in _MODELS
        or type(rows) is not list
        or type(input_internal) is not list
        or payload.get("independent_tasks") != 51
        or payload.get("row_count") != len(rows)
        or tuple(input_internal) != _INTERNAL_VARIABLES_BY_VIEW.get(view_id)
    ):
        raise ValueError("discovery-v2 matrix payload failed validation")
    projection = (
        tuple(str(item) for item in input_internal)
        if projected_internal_ids is None
        else projected_internal_ids
    )
    if (
        len(projection) != len(set(projection))
        or not set(projection) <= set(input_internal)
        or _MECHANISM not in projection
        or _OUTCOME_BY_VIEW[view_id] not in projection
    ):
        raise ValueError("discovery-v2 variable projection failed validation")
    variables = _variables(payload, producer_sha256, projection)
    variable_ids = tuple(item.variable_id for item in variables)
    input_index = {str(variable_id): index for index, variable_id in enumerate(input_internal)}
    observations = []
    bindings = []
    task_ids = set()
    for row in rows:
        if type(row) is not dict or type(row.get("values")) is not list:
            raise ValueError("discovery-v2 matrix row failed validation")
        input_values = row["values"]
        values = tuple(int(input_values[input_index[variable_id]]) for variable_id in variable_ids)
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
    if len(task_ids) != payload["independent_tasks"]:
        raise ValueError("discovery-v2 independent task count failed validation")
    table = CausalTableRecord.from_jci_content(
        scope_id="scope.five_cwe_policy_mechanism_v2",
        cwe="CWE-POOLED",
        model_id=model_id,
        variables=variables,
        independent_task_count=len(task_ids),
        observation_payload=observations,
    )
    bindings.sort(key=lambda item: str(item["assignment_id"]))
    matrix = np.asarray(tuple(item["values"] for item in bindings), dtype=np.int64)
    if matrix.shape != (len(rows), len(variables)) or not matrix.flags.c_contiguous:
        raise ValueError("discovery-v2 matrix construction failed validation")
    matrix.flags.writeable = False
    return table, matrix, tuple(bindings)


def _base_background(table: CausalTableRecord) -> BackgroundKnowledgeRecord:
    tiered = tuple(item for item in table.variables if item.variable_id != "c.arm")
    variable_ids = tuple(item.variable_id for item in table.variables)
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
        variable_ids=variable_ids,
        tiers=tiers,
        unconstrained_variable_ids=("c.arm",) if "c.arm" in variable_ids else (),
        forbidden_directions=forbidden,
        forbidden_adjacencies=(),
        required_directions=(),
    )


def _edge_by_pair(pag: PAGRecord) -> dict[frozenset[str], PAGEdgeRecord]:
    return {frozenset({edge.left, edge.right}): edge for edge in pag.edges}


def _has_possible_xzy(pag: PAGRecord, outcome: str, *, source: str = _SOURCE) -> bool:
    edges = _edge_by_pair(PAGRecord.model_validate(pag))
    first = edges.get(frozenset({source, _MECHANISM}))
    second = edges.get(frozenset({_MECHANISM, outcome}))
    return bool(
        first is not None
        and second is not None
        and edge_allows_possible_direction(first, source, _MECHANISM)
        and edge_allows_possible_direction(second, _MECHANISM, outcome)
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


def run_randomized_discovery_v2_reference_fci(
    *,
    table_dir: Path,
    analysis_config_path: Path,
    model_id: str,
    view_id: str,
    output_dir: Path,
    command_argv: tuple[str, ...],
    runner: FCIRunner | None = None,
) -> dict[str, object]:
    table_dir = table_dir.resolve()
    analysis_config_path = analysis_config_path.resolve()
    output_dir = output_dir.resolve()
    if (
        output_dir.exists()
        or not table_dir.is_dir()
        or model_id not in _MODELS
        or view_id not in _VIEWS
    ):
        raise ValueError("discovery-v2 reference invocation failed validation")
    table_manifest_sha256 = _verify_directory_manifest(table_dir)
    table_report = _read_json(table_dir / "report.json")
    analysis = _validated_analysis(analysis_config_path)
    if (
        table_report.get("status") != "DISCOVERY_V2_TABLES_COMPLETE"
        or table_report.get("counts", {}).get("tasks_per_model") != 51
        or table_report.get("counts", {}).get("joined_rows") != 408
    ):
        raise ValueError("discovery-v2 table population failed validation")
    model_stem = "qwen7b" if model_id.startswith("qwen") else "phi14b"
    matrix_path = table_dir / f"matrix-{model_stem}-{view_id}.json"
    payload = _read_json(matrix_path)
    source = str(analysis["candidate_freeze"]["source_variable"])
    projection_record = analysis.get("variable_projection_by_view")
    projected_internal_ids = (
        None
        if projection_record is None
        else tuple(str(item) for item in projection_record[view_id])
    )
    producer_sha256 = canonical_sha256(
        {
            "policy": _POLICY,
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "table_manifest_sha256": table_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
        }
    )
    table, matrix, bindings = _table_and_matrix(
        payload,
        producer_sha256=producer_sha256,
        projected_internal_ids=projected_internal_ids,
    )
    if source not in {item.variable_id for item in table.variables}:
        raise ValueError("discovery-v2 candidate source projection failed validation")
    config = _config(analysis)
    base = _base_background(table)
    active_runner = SpawnedFCIRunner() if runner is None else runner
    variable_ids = {item.variable_id for item in table.variables}
    raw_kind = PAGRunKind.JCI_RAW if "c.arm" in variable_ids else PAGRunKind.OBSERVATIONAL_REFERENCE
    raw_pag = active_runner.run(matrix, table, base, config, raw_kind)
    validate_pag_against_background(raw_pag, base)
    constrained_pag = None
    jci = None
    if "c.arm" in variable_ids:
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
        constrained_pag = active_runner.run(
            matrix,
            table,
            jci.materialized_background_knowledge,
            config,
            PAGRunKind.JCI_CONSTRAINED,
        )
        validate_pag_against_background(constrained_pag, jci.materialized_background_knowledge)
    outcome = _OUTCOME_BY_VIEW[view_id]
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "causal-table.json", table)
    _write_jsonl(output_dir / "row-bindings.jsonl", bindings)
    _write_json(output_dir / "base-background-knowledge.json", base)
    _write_json(output_dir / "raw-pag.json", raw_pag)
    if jci is not None and constrained_pag is not None:
        _write_json(output_dir / "jci-background-knowledge.json", jci)
        _write_json(output_dir / "jci-constrained-pag.json", constrained_pag)
        _write_jsonl(
            output_dir / "jci-orientation-delta.jsonl",
            _orientation_delta(raw_pag, constrained_pag),
        )
    _write_json(
        output_dir / "provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "policy": _POLICY,
            "table_manifest_sha256": table_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "matrix_sha256": hashlib.sha256(matrix.tobytes(order="C")).hexdigest(),
            "matrix_shape": list(matrix.shape),
            "candidate_path_source": "raw_pag",
            "candidate_source_variable": source,
            "variable_projection": [item.variable_id for item in table.variables],
            "required_directions": [],
            "required_adjacencies": [],
        },
    )
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "DISCOVERY_V2_REFERENCE_FCI_COMPLETE",
        "model_id": model_id,
        "view_id": view_id,
        "rows": table.row_count,
        "independent_tasks": table.independent_task_count,
        "variables": len(table.variables),
        "raw_pag_edges": len(raw_pag.edges),
        "jci_constrained_pag_edges": (
            len(constrained_pag.edges) if constrained_pag is not None else None
        ),
        "candidate_source_variable": source,
        "raw_possible_xzy": _has_possible_xzy(raw_pag, outcome, source=source),
        "jci_possible_xzy": (
            _has_possible_xzy(constrained_pag, outcome, source=source)
            if constrained_pag is not None
            else None
        ),
        "bootstrap_runs": 0,
        "scientific_claim_allowed": False,
        "next_stage": "task_cluster_bootstrap_if_reference_path_present",
    }
    _write_json(output_dir / "report.json", report)
    _write_json(
        output_dir / "artifact-manifest.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "files": [
                {"path": path.name, "sha256": sha256_file(path)}
                for path in sorted(output_dir.iterdir())
                if path.is_file()
            ],
        },
    )
    return report


__all__ = ["run_randomized_discovery_v2_reference_fci"]
