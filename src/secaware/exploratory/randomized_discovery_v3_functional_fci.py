"""Reference FCI/JCI for the 93-task security-mechanism to functional-outcome view."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import numpy as np

from secaware.causal.background import validate_pag_against_background
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner
from secaware.experiments.held_out_policy_analysis import _verify_directory_manifest
from secaware.exploratory.randomized_discovery_v2_fci import (
    _base_background,
    _config,
    _environment,
    _has_possible_xzy,
    _orientation_delta,
    _read_json,
    _write_json,
    _write_jsonl,
)
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.causal import (
    CausalTableRecord,
    CausalVariableSpec,
    JCIBackgroundKnowledgeRecord,
    PAGRunKind,
    VariableRole,
    jci_row_id_from_content,
)

_SCHEMA_VERSION = "1.0"
_POLICY = "five-cwe-randomized-discovery-v3-functional-reference-fci-v1"
_MODELS = ("qwen2.5-coder-7b-instruct", "phi-4-14b")
_VIEWS = ("target_noop_functional", "full_jci_functional")
_SOURCE = "c.arm"
_MECHANISM = "z.target_mechanism_realized"
_OUTCOME = "y.discovery_functional"
_VARIABLE_IDS = (_SOURCE, _MECHANISM, _OUTCOME)


def _validated_analysis(path: Path) -> dict[str, Any]:
    analysis = _read_json(path)
    if (
        analysis.get("schema_version") != _SCHEMA_VERSION
        or analysis.get("analysis_id") != "five_cwe_randomized_discovery_v3_functional_fci_v1"
        or analysis.get("status") != "EXPLORATORY_METHOD_DEVELOPMENT_FROZEN_BEFORE_FUNCTIONAL_FCI"
        or analysis.get("development_population")
        != {
            "table_bundle": "five_cwe_discovery_v3_functional_table_v1",
            "tasks_per_model": 93,
            "outcomes_previously_observed": True,
            "scientific_confirmation_allowed": False,
            "model_pooling": "forbidden",
        }
        or analysis.get("model_strata") != list(_MODELS)
        or analysis.get("views")
        != {"primary": "target_noop_functional", "sensitivity": "full_jci_functional"}
        or analysis.get("semantic_provenance_boundary")
        != {
            "z_security_y_identity_rows": 744,
            "security_or_joint_y": "forbidden",
            "functional_y_source": "llm_judge_or_functional_outcome",
            "mechanism_z_source": "arm_blind_code_mechanism_trace",
        }
        or analysis.get("background_knowledge")
        != {
            "jci_context_variable": _SOURCE,
            "jci_assumption": "jci.randomized_context_exogeneity.v1",
            "temporal_tiers": {_MECHANISM: 2, _OUTCOME: 3},
            "required_directions": [],
            "required_adjacencies": [],
        }
        or analysis.get("candidate_freeze")
        != {
            "source_variable": _SOURCE,
            "required_mechanism_variable": _MECHANISM,
            "outcome_variable": _OUTCOME,
            "target_noop_estimand": "target_patch_vs_noop_rewrite",
            "minimum_stability": 0.8,
            "confirmation_outcomes_may_select_or_rescue": False,
        }
        or analysis.get("fci", {}).get("bootstrap_unit") != "complete_task_block"
        or analysis.get("independent_validation_required") is not True
    ):
        raise ValueError("discovery-v3 functional analysis failed validation")
    config = _config(analysis)
    if (
        config.alpha != 0.05
        or config.bootstrap_samples != 200
        or config.stability_threshold != 0.8
        or config.max_failed_bootstrap_fraction != 0.1
    ):
        raise ValueError("discovery-v3 functional FCI contract failed validation")
    return analysis


def _variables(
    producer_sha256: str,
    *,
    scope_id: str = "scope.five_cwe_mechanism_function_v3",
) -> tuple[CausalVariableSpec, ...]:
    context = CausalVariableSpec(
        schema_version=_SCHEMA_VERSION,
        variable_id=_SOURCE,
        role=VariableRole.C,
        states=(
            "target_patch",
            "noop_rewrite",
            "length_matched_placebo",
            "generic_security_reminder",
        ),
        source_query_id="assignment.arm_role.v1",
        scope_id=scope_id,
        temporal_tier=0,
        adjacency_type="jci_context",
        producer_sha256=producer_sha256,
    )
    declared = []
    for variable_id in (_MECHANISM, _OUTCOME):
        declaration = declaration_by_id(variable_id)
        declared.append(
            CausalVariableSpec(
                schema_version=_SCHEMA_VERSION,
                variable_id=declaration.variable_id,
                role=declaration.role,
                states=declaration.states,
                source_query_id=declaration.query_id,
                scope_id=scope_id,
                temporal_tier=declaration.tier,
                adjacency_type=declaration.adjacency_type,
                producer_sha256=declaration_sha256(declaration),
            )
        )
    return tuple(sorted((context, *declared), key=lambda item: item.variable_id))


def _table_and_matrix(
    payload: dict[str, Any],
    *,
    producer_sha256: str,
) -> tuple[CausalTableRecord, np.ndarray, tuple[dict[str, object], ...]]:
    return _table_and_matrix_for_population(
        payload,
        producer_sha256=producer_sha256,
        expected_tasks=93,
        scope_id="scope.five_cwe_mechanism_function_v3",
    )


def _table_and_matrix_for_population(
    payload: dict[str, Any],
    *,
    producer_sha256: str,
    expected_tasks: int,
    scope_id: str,
) -> tuple[CausalTableRecord, np.ndarray, tuple[dict[str, object], ...]]:
    view_id = str(payload.get("view_id"))
    rows = payload.get("rows")
    input_ids = payload.get("internal_variable_ids")
    arms_per_task = 2 if view_id == "target_noop_functional" else 4
    expected_rows = expected_tasks * arms_per_task
    if (
        view_id not in _VIEWS
        or payload.get("model_id") not in _MODELS
        or input_ids != list(_VARIABLE_IDS)
        or type(rows) is not list
        or payload.get("independent_tasks") != expected_tasks
        or payload.get("row_count") != expected_rows
        or len(rows) != expected_rows
    ):
        raise ValueError("discovery-v3 functional matrix payload failed validation")
    variables = _variables(producer_sha256, scope_id=scope_id)
    variable_ids = tuple(item.variable_id for item in variables)
    index = {variable_id: position for position, variable_id in enumerate(input_ids)}
    observations = []
    bindings = []
    task_ids = set()
    for row in rows:
        if type(row) is not dict or type(row.get("values")) is not list:
            raise ValueError("discovery-v3 functional matrix row failed validation")
        values = tuple(int(row["values"][index[variable_id]]) for variable_id in variable_ids)
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
    if len(task_ids) != expected_tasks:
        raise ValueError("discovery-v3 functional task count failed validation")
    table = CausalTableRecord.from_jci_content(
        scope_id=scope_id,
        cwe="CWE-POOLED",
        model_id=str(payload["model_id"]),
        variables=variables,
        independent_task_count=expected_tasks,
        observation_payload=observations,
    )
    bindings.sort(key=lambda item: str(item["assignment_id"]))
    matrix = np.asarray(tuple(item["values"] for item in bindings), dtype=np.int64)
    if matrix.shape != (expected_rows, 3):
        raise ValueError("discovery-v3 functional matrix construction failed validation")
    matrix = np.array(matrix, dtype=np.int64, order="C", copy=True)
    matrix.flags.writeable = False
    return table, matrix, tuple(bindings)


def run_randomized_discovery_v3_functional_fci(
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
    if output_dir.exists() or model_id not in _MODELS or view_id not in _VIEWS:
        raise ValueError("discovery-v3 functional FCI invocation failed validation")
    table_manifest_sha256 = _verify_directory_manifest(table_dir)
    table_report = _read_json(table_dir / "report.json")
    analysis = _validated_analysis(analysis_config_path)
    if (
        table_report.get("status") != "DISCOVERY_V3_FUNCTIONAL_TABLES_COMPLETE"
        or table_report.get("counts", {}).get("combined_rows") != 744
        or table_report.get("counts", {}).get("tasks_per_model") != 93
        or table_report.get("semantic_leakage_detected") is not True
        or table_report.get("security_or_joint_y_excluded") is not True
    ):
        raise ValueError("discovery-v3 functional table report failed validation")
    stem = "qwen7b" if model_id.startswith("qwen") else "phi14b"
    matrix_path = table_dir / f"matrix-{stem}-{view_id}.json"
    payload = _read_json(matrix_path)
    producer_sha256 = canonical_sha256(
        {
            "policy": _POLICY,
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "table_manifest_sha256": table_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
        }
    )
    table, matrix, bindings = _table_and_matrix(payload, producer_sha256=producer_sha256)
    config = _config(analysis)
    base = _base_background(table)
    active_runner = SpawnedFCIRunner() if runner is None else runner
    raw_pag = active_runner.run(matrix, table, base, config, PAGRunKind.JCI_RAW)
    validate_pag_against_background(raw_pag, base)
    jci = JCIBackgroundKnowledgeRecord.from_base(
        base,
        assumption_ids=("jci.randomized_context_exogeneity.v1",),
        added_forbidden_directions=tuple(sorted(((_MECHANISM, _SOURCE), (_OUTCOME, _SOURCE)))),
    )
    constrained = active_runner.run(
        matrix,
        table,
        jci.materialized_background_knowledge,
        config,
        PAGRunKind.JCI_CONSTRAINED,
    )
    validate_pag_against_background(constrained, jci.materialized_background_knowledge)
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "causal-table.json", table)
    _write_jsonl(output_dir / "row-bindings.jsonl", bindings)
    _write_json(output_dir / "base-background-knowledge.json", base)
    _write_json(output_dir / "raw-pag.json", raw_pag)
    _write_json(output_dir / "jci-background-knowledge.json", jci)
    _write_json(output_dir / "jci-constrained-pag.json", constrained)
    _write_jsonl(
        output_dir / "jci-orientation-delta.jsonl",
        _orientation_delta(raw_pag, constrained),
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
            "semantic_leakage_boundary": "security_and_joint_y_forbidden",
            "required_directions": [],
            "required_adjacencies": [],
        },
    )
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "DISCOVERY_V3_FUNCTIONAL_REFERENCE_FCI_COMPLETE",
        "model_id": model_id,
        "view_id": view_id,
        "rows": table.row_count,
        "independent_tasks": table.independent_task_count,
        "variables": len(table.variables),
        "raw_pag_edges": len(raw_pag.edges),
        "jci_constrained_pag_edges": len(constrained.edges),
        "raw_possible_czy": _has_possible_xzy(raw_pag, _OUTCOME, source=_SOURCE),
        "jci_possible_czy": _has_possible_xzy(constrained, _OUTCOME, source=_SOURCE),
        "bootstrap_runs": 0,
        "scientific_claim_allowed": False,
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


__all__ = ["run_randomized_discovery_v3_functional_fci"]
