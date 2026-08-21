"""FCI/JCI replication analysis for the frozen 55-task independent sample."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

import numpy as np

from secaware.causal.background import validate_pag_against_background
from secaware.causal.paths import edge_allows_possible_direction, endpoint_marks_compatible
from secaware.discovery.fci_supervisor import FCIRunner, SpawnedFCIRunner
from secaware.experiments.held_out_policy_analysis import _verify_directory_manifest
from secaware.exploratory.randomized_discovery_bootstrap import _manifest
from secaware.exploratory.randomized_discovery_v2_fci import (
    _base_background,
    _config,
    _environment,
    _orientation_delta,
    _read_json,
    _write_json,
    _write_jsonl,
)
from secaware.exploratory.randomized_discovery_v3_functional_fci import (
    _table_and_matrix_for_population,
    _validated_analysis,
)
from secaware.pipeline.artifact import canonical_sha256, sha256_file
from secaware.schema.causal import (
    CausalTableRecord,
    EndpointMark,
    JCIBackgroundKnowledgeRecord,
    PAGRecord,
    PAGRunKind,
    jci_row_id_from_content,
)

_SCHEMA_VERSION = "1.0"
_POLICY = "five-cwe-independent-validation-mechanism-function-fci-v1"
_MODEL = "phi-4-14b"
_VIEW = "full_jci_functional"
_CONTEXT = "c.arm"
_SOURCE = "z.target_mechanism_realized"
_TARGET = "y.discovery_functional"
_EXPECTED_TASKS = 55
_EXPECTED_ROWS = 220


def _validated_config(repo_root: Path, path: Path) -> tuple[dict[str, Any], Path, Path]:
    config = _read_json(path)
    if (
        config.get("schema_version") != _SCHEMA_VERSION
        or config.get("analysis_id") != "five_cwe_independent_validation_mechanism_function_fci_v1"
        or config.get("model_id") != _MODEL
        or config.get("view_id") != _VIEW
        or config.get("expected_tasks") != _EXPECTED_TASKS
        or config.get("expected_rows") != _EXPECTED_ROWS
        or config.get("source_variable") != _SOURCE
        or config.get("target_variable") != _TARGET
        or config.get("reference_marks") != ["tail", "arrow"]
        or config.get("required_directions") != []
        or config.get("required_adjacencies") != []
        or config.get("jci_assumption") != "jci.randomized_context_exogeneity.v1"
    ):
        raise ValueError("independent validation FCI config failed validation")
    inherited = config.get("inherited_fci_config")
    runtime = config.get("runtime_freeze")
    if type(inherited) is not dict or type(runtime) is not dict:
        raise ValueError("independent validation FCI provenance failed validation")
    inherited_path = (repo_root / str(inherited.get("path"))).resolve()
    runtime_path = (repo_root / str(runtime.get("path"))).resolve()
    for target in (inherited_path, runtime_path):
        try:
            target.relative_to(repo_root)
        except ValueError:
            raise ValueError("independent validation FCI input escaped repository") from None
    if (
        not inherited_path.is_file()
        or sha256_file(inherited_path) != inherited.get("sha256")
        or not runtime_path.is_dir()
        or sha256_file(runtime_path / "artifact-manifest.json") != runtime.get("sha256")
    ):
        raise ValueError("independent validation FCI input digest failed validation")
    inherited_analysis = _validated_analysis(inherited_path)
    inherited_config = _config(inherited_analysis)
    if (
        inherited_config.alpha != 0.05
        or inherited_config.ci_test != "gsq"
        or inherited_config.bootstrap_samples != 200
        or inherited_config.stability_threshold != 0.8
        or inherited_config.max_failed_bootstrap_fraction != 0.1
    ):
        raise ValueError("independent validation inherited FCI contract failed validation")
    runtime_policy = _read_json(runtime_path / "runtime-policy.json")
    if (
        runtime_policy.get("source_variable") != _SOURCE
        or runtime_policy.get("target_variable") != _TARGET
        or runtime_policy.get("reference_marks") != config["reference_marks"]
    ):
        raise ValueError("independent validation frozen edge failed validation")
    return config, inherited_path, runtime_path


def _edge(pag: PAGRecord):
    for edge in pag.edges:
        if {edge.left, edge.right} == {_SOURCE, _TARGET}:
            return edge
    return None


def _matches_frozen_edge(pag: PAGRecord) -> bool:
    edge = _edge(pag)
    if edge is None or not edge_allows_possible_direction(edge, _SOURCE, _TARGET):
        return False
    frozen = (EndpointMark.TAIL, EndpointMark.ARROW)
    return all(
        endpoint_marks_compatible(reference, observed)
        for reference, observed in zip(frozen, edge.marks_from(_SOURCE, _TARGET), strict=True)
    )


def run_independent_validation_analysis_fci(
    *,
    repo_root: Path,
    table_dir: Path,
    analysis_config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
    runner: FCIRunner | None = None,
) -> dict[str, object]:
    repo_root = repo_root.resolve()
    table_dir = table_dir.resolve()
    analysis_config_path = analysis_config_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ValueError("independent validation FCI output already exists")
    analysis, inherited_path, runtime_path = _validated_config(repo_root, analysis_config_path)
    table_manifest_sha256 = _verify_directory_manifest(table_dir)
    table_report = _read_json(table_dir / "report.json")
    if (
        table_report.get("status") != "INDEPENDENT_VALIDATION_ANALYSIS_TABLE_COMPLETE"
        or table_report.get("counts", {}).get("tasks") != _EXPECTED_TASKS
        or table_report.get("counts", {}).get("assignments") != _EXPECTED_ROWS
        or table_report.get("counts", {}).get("errors") != 0
    ):
        raise ValueError("independent validation FCI table failed validation")
    matrix_path = table_dir / "matrix-phi14b-full_jci_functional.json"
    payload = _read_json(matrix_path)
    producer_sha256 = canonical_sha256(
        {
            "policy": _POLICY,
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "inherited_fci_config_sha256": sha256_file(inherited_path),
            "runtime_freeze_manifest_sha256": sha256_file(runtime_path / "artifact-manifest.json"),
            "table_manifest_sha256": table_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
        }
    )
    table, matrix, bindings = _table_and_matrix_for_population(
        payload,
        producer_sha256=producer_sha256,
        expected_tasks=_EXPECTED_TASKS,
        scope_id="scope.five_cwe_independent_mechanism_function_v1",
    )
    inherited_analysis = _validated_analysis(inherited_path)
    fci_config = _config(inherited_analysis)
    base = _base_background(table)
    active_runner = SpawnedFCIRunner() if runner is None else runner
    raw_pag = active_runner.run(matrix, table, base, fci_config, PAGRunKind.JCI_RAW)
    validate_pag_against_background(raw_pag, base)
    jci = JCIBackgroundKnowledgeRecord.from_base(
        base,
        assumption_ids=(analysis["jci_assumption"],),
        added_forbidden_directions=((_SOURCE, _CONTEXT), (_TARGET, _CONTEXT)),
    )
    constrained = active_runner.run(
        matrix,
        table,
        jci.materialized_background_knowledge,
        fci_config,
        PAGRunKind.JCI_CONSTRAINED,
    )
    validate_pag_against_background(constrained, jci.materialized_background_knowledge)
    raw_edge = _edge(raw_pag)
    constrained_edge = _edge(constrained)
    raw_marks = (
        [] if raw_edge is None else [mark.value for mark in raw_edge.marks_from(_SOURCE, _TARGET)]
    )
    constrained_marks = (
        []
        if constrained_edge is None
        else [mark.value for mark in constrained_edge.marks_from(_SOURCE, _TARGET)]
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "causal-table.json", table)
    _write_jsonl(output_dir / "row-bindings.jsonl", bindings)
    _write_json(output_dir / "base-background-knowledge.json", base)
    _write_json(output_dir / "raw-pag.json", raw_pag)
    _write_json(output_dir / "jci-background-knowledge.json", jci)
    _write_json(output_dir / "jci-constrained-pag.json", constrained)
    _write_jsonl(
        output_dir / "jci-orientation-delta.jsonl", _orientation_delta(raw_pag, constrained)
    )
    _write_json(
        output_dir / "frozen-edge-reference-check.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "source_variable": _SOURCE,
            "target_variable": _TARGET,
            "frozen_reference_marks": analysis["reference_marks"],
            "raw_pag_marks": raw_marks,
            "raw_pag_frozen_edge_match": _matches_frozen_edge(raw_pag),
            "jci_constrained_pag_marks": constrained_marks,
            "jci_constrained_pag_frozen_edge_match": _matches_frozen_edge(constrained),
            "selection_role": "validation_only_no_hypothesis_selection",
        },
    )
    _write_json(
        output_dir / "provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "policy": _POLICY,
            "table_manifest_sha256": table_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "inherited_fci_config_sha256": sha256_file(inherited_path),
            "runtime_freeze_manifest_sha256": sha256_file(runtime_path / "artifact-manifest.json"),
            "matrix_sha256": hashlib.sha256(matrix.tobytes(order="C")).hexdigest(),
            "matrix_shape": list(matrix.shape),
            "required_directions": [],
            "required_adjacencies": [],
            "candidate_selection_allowed": False,
        },
    )
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "INDEPENDENT_VALIDATION_REFERENCE_FCI_COMPLETE",
        "model_id": _MODEL,
        "view_id": _VIEW,
        "rows": table.row_count,
        "independent_tasks": table.independent_task_count,
        "variables": len(table.variables),
        "raw_pag_edges": len(raw_pag.edges),
        "jci_constrained_pag_edges": len(constrained.edges),
        "raw_pag_frozen_edge_match": _matches_frozen_edge(raw_pag),
        "jci_constrained_pag_frozen_edge_match": _matches_frozen_edge(constrained),
        "bootstrap_runs": 0,
        "replication_decision": "pending_task_cluster_bootstrap",
        "scientific_claim_allowed": False,
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


def run_independent_validation_prompt_only_fci(
    *,
    repo_root: Path,
    table_dir: Path,
    mechanism_reference_dir: Path,
    analysis_config_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
    runner: FCIRunner | None = None,
) -> dict[str, object]:
    """Run the predeclared Prompt-only comparator without selecting a new hypothesis."""

    repo_root = repo_root.resolve()
    table_dir = table_dir.resolve()
    mechanism_reference_dir = mechanism_reference_dir.resolve()
    analysis_config_path = analysis_config_path.resolve()
    output_dir = output_dir.resolve()
    if output_dir.exists():
        raise ValueError("independent validation Prompt-only output already exists")
    analysis, inherited_path, runtime_path = _validated_config(repo_root, analysis_config_path)
    table_manifest_sha256 = _verify_directory_manifest(table_dir)
    mechanism_reference_manifest_sha256 = _verify_directory_manifest(mechanism_reference_dir)
    mechanism_reference_report = _read_json(mechanism_reference_dir / "report.json")
    table_report = _read_json(table_dir / "report.json")
    if (
        table_report.get("status") != "INDEPENDENT_VALIDATION_ANALYSIS_TABLE_COMPLETE"
        or table_report.get("counts", {}).get("tasks") != _EXPECTED_TASKS
        or table_report.get("counts", {}).get("assignments") != _EXPECTED_ROWS
        or mechanism_reference_report.get("status")
        != "INDEPENDENT_VALIDATION_REFERENCE_FCI_COMPLETE"
        or mechanism_reference_report.get("independent_tasks") != _EXPECTED_TASKS
    ):
        raise ValueError("independent validation Prompt-only table failed validation")
    full_table = CausalTableRecord.model_validate(
        _read_json(mechanism_reference_dir / "causal-table.json")
    )
    variables = tuple(
        variable for variable in full_table.variables if variable.variable_id in {_CONTEXT, _TARGET}
    )
    matrix_path = table_dir / "matrix-phi14b-full_jci_functional.json"
    payload = _read_json(matrix_path)
    input_ids = payload.get("internal_variable_ids")
    rows = payload.get("rows")
    if type(input_ids) is not list or type(rows) is not list or len(rows) != _EXPECTED_ROWS:
        raise ValueError("independent validation Prompt-only matrix failed validation")
    input_index = {str(variable_id): index for index, variable_id in enumerate(input_ids)}
    observations = []
    bindings = []
    for row in rows:
        values = tuple(int(row["values"][input_index[item.variable_id]]) for item in variables)
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
    table = CausalTableRecord.from_jci_content(
        scope_id=full_table.scope_id,
        cwe="CWE-POOLED",
        model_id=_MODEL,
        variables=variables,
        independent_task_count=_EXPECTED_TASKS,
        observation_payload=observations,
    )
    bindings.sort(key=lambda row: str(row["assignment_id"]))
    matrix = np.asarray(tuple(row["values"] for row in bindings), dtype=np.int64)
    if matrix.shape != (_EXPECTED_ROWS, 2):
        raise ValueError("independent validation Prompt-only construction failed validation")
    matrix = np.array(matrix, dtype=np.int64, order="C", copy=True)
    matrix.flags.writeable = False
    inherited_analysis = _validated_analysis(inherited_path)
    fci_config = _config(inherited_analysis)
    base = _base_background(table)
    active_runner = SpawnedFCIRunner() if runner is None else runner
    raw_pag = active_runner.run(matrix, table, base, fci_config, PAGRunKind.JCI_RAW)
    validate_pag_against_background(raw_pag, base)
    jci = JCIBackgroundKnowledgeRecord.from_base(
        base,
        assumption_ids=(analysis["jci_assumption"],),
        added_forbidden_directions=((_TARGET, _CONTEXT),),
    )
    constrained = active_runner.run(
        matrix,
        table,
        jci.materialized_background_knowledge,
        fci_config,
        PAGRunKind.JCI_CONSTRAINED,
    )
    validate_pag_against_background(constrained, jci.materialized_background_knowledge)
    raw_edge = next(iter(raw_pag.edges), None)
    constrained_edge = next(iter(constrained.edges), None)
    raw_possible = raw_edge is not None and edge_allows_possible_direction(
        raw_edge, _CONTEXT, _TARGET
    )
    constrained_possible = constrained_edge is not None and edge_allows_possible_direction(
        constrained_edge, _CONTEXT, _TARGET
    )
    output_dir.mkdir(parents=True, exist_ok=False)
    _write_json(output_dir / "causal-table.json", table)
    _write_jsonl(output_dir / "row-bindings.jsonl", bindings)
    _write_json(output_dir / "base-background-knowledge.json", base)
    _write_json(output_dir / "raw-pag.json", raw_pag)
    _write_json(output_dir / "jci-background-knowledge.json", jci)
    _write_json(output_dir / "jci-constrained-pag.json", constrained)
    _write_jsonl(
        output_dir / "jci-orientation-delta.jsonl", _orientation_delta(raw_pag, constrained)
    )
    _write_json(
        output_dir / "provenance.json",
        {
            "schema_version": _SCHEMA_VERSION,
            "policy": "five-cwe-independent-validation-prompt-only-comparator-v1",
            "table_manifest_sha256": table_manifest_sha256,
            "mechanism_reference_manifest_sha256": mechanism_reference_manifest_sha256,
            "matrix_artifact_sha256": sha256_file(matrix_path),
            "analysis_config_sha256": sha256_file(analysis_config_path),
            "inherited_fci_config_sha256": sha256_file(inherited_path),
            "runtime_freeze_manifest_sha256": sha256_file(runtime_path / "artifact-manifest.json"),
            "matrix_sha256": hashlib.sha256(matrix.tobytes(order="C")).hexdigest(),
            "matrix_shape": list(matrix.shape),
            "removed_variable": _SOURCE,
            "candidate_selection_allowed": False,
        },
    )
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(output_dir / "environment.json", _environment())
    report: dict[str, object] = {
        "schema_version": _SCHEMA_VERSION,
        "status": "INDEPENDENT_VALIDATION_PROMPT_ONLY_FCI_COMPLETE",
        "model_id": _MODEL,
        "rows": table.row_count,
        "independent_tasks": table.independent_task_count,
        "variables": len(table.variables),
        "raw_pag_edges": len(raw_pag.edges),
        "jci_constrained_pag_edges": len(constrained.edges),
        "raw_possible_context_to_function": raw_possible,
        "jci_possible_context_to_function": constrained_possible,
        "candidate_yield": int(raw_possible),
        "comparison_role": "prompt_only_sensitivity_no_hypothesis_selection",
        "scientific_claim_allowed": False,
    }
    _write_json(output_dir / "report.json", report)
    _manifest(output_dir)
    return report


__all__ = [
    "run_independent_validation_analysis_fci",
    "run_independent_validation_prompt_only_fci",
]
