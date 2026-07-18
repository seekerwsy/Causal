from __future__ import annotations

import numpy as np
import pandas as pd

from secaware.causal.background import validate_pag_against_background
from secaware.causal.jci import (
    JCIAnalysisResult,
    analyze_jci_stratum,
    build_jci_background,
    matrix_for_exact_rows,
    validate_jci_analysis_result,
)
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import FCIDiscoveryConfig
from secaware.discovery.causal_learn_backend import run_causal_learn_fci
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    CausalVariableSpec,
    JCIContextSpec,
    PAGRecord,
    PAGRunKind,
    VariableRole,
    jci_row_id_from_content,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.outcomes import JCIObservationRecord
from synthetic.scm_fixtures import deterministic_context_scm


_ARM_ROLES = (
    ArmRole.TARGET_PATCH,
    ArmRole.NOOP_REWRITE,
    ArmRole.LENGTH_MATCHED_PLACEBO,
    ArmRole.GENERIC_SECURITY_REMINDER,
)


class _RealCausalLearnRunner:
    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        return run_causal_learn_fci(matrix, table, knowledge, config, run_kind)


def _system_variable(variable_id: str) -> CausalVariableSpec:
    declaration = declaration_by_id(variable_id)
    return CausalVariableSpec(
        schema_version="1.0",
        variable_id=declaration.variable_id,
        role=declaration.role,
        states=declaration.states,
        source_query_id=declaration.query_id,
        scope_id="scope.cwe_89",
        temporal_tier=declaration.tier,
        adjacency_type=declaration.adjacency_type,
        producer_sha256=declaration_sha256(declaration),
    )


def _jci_table_and_rows(
    frame: pd.DataFrame,
) -> tuple[CausalTableRecord, tuple[JCIObservationRecord, ...]]:
    context = JCIContextSpec(arm_roles=_ARM_ROLES, category_codes=(0, 1, 2, 3))
    variables = (
        CausalVariableSpec(
            schema_version="1.0",
            variable_id=context.variable_id,
            role=VariableRole.C,
            states=tuple(role.value for role in context.arm_roles),
            source_query_id="assignment.arm_role.v1",
            scope_id="scope.cwe_89",
            temporal_tier=0,
            adjacency_type="jci_context",
            producer_sha256="a" * 64,
        ),
        _system_variable("x.safety.sql_parameterization"),
        _system_variable("y.secure_functional"),
    )
    target_spec_id = "target_" + "1" * 64
    arm_protocol_id = "arm_protocol_" + "2" * 64
    tasks_per_arm = len(frame) // len(_ARM_ROLES)
    payload = []
    for index, row in frame.iterrows():
        task_index = index % tasks_per_arm
        assignment_id = f"assignment_{index + 3:064x}"
        task_id = f"synthetic-jci-task-{task_index:05d}"
        target_instance_id = f"target_instance_{task_index + 4:064x}"
        protocol_instance_id = f"protocol_instance_{task_index + 5:064x}"
        values = (
            int(row["c.arm"]),
            int(row["x.target_feature"]),
            int(row["y.secure_functional"]),
        )
        payload.append(
            (
                jci_row_id_from_content(
                    assignment_id=assignment_id,
                    task_id=task_id,
                    target_spec_id=target_spec_id,
                    target_instance_id=target_instance_id,
                    arm_protocol_id=arm_protocol_id,
                    protocol_instance_id=protocol_instance_id,
                    values=values,
                ),
                assignment_id,
                task_id,
                target_spec_id,
                target_instance_id,
                arm_protocol_id,
                protocol_instance_id,
                values,
            )
        )
    table = CausalTableRecord.from_jci_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="synthetic-model",
        variables=variables,
        independent_task_count=tasks_per_arm,
        observation_payload=payload,
    )
    rows = tuple(
        sorted(
            (
                JCIObservationRecord.from_content(
                    table_id=table.table_id,
                    assignment_id=assignment_id,
                    task_id=task_id,
                    target_spec_id=target_spec_id,
                    target_instance_id=target_instance_id,
                    arm_protocol_id=arm_protocol_id,
                    protocol_instance_id=protocol_instance_id,
                    values=values,
                )
                for (
                    _row_id,
                    assignment_id,
                    task_id,
                    target_spec_id,
                    target_instance_id,
                    arm_protocol_id,
                    protocol_instance_id,
                    values,
                ) in payload
            ),
            key=lambda item: item.row_id,
        )
    )
    return table, rows


def _config() -> FCIDiscoveryConfig:
    return FCIDiscoveryConfig(
        alpha=0.01,
        depth=2,
        max_path_length=4,
        min_independent_tasks=20,
    )


def _canonical(result: JCIAnalysisResult) -> dict[str, object]:
    return {
        "raw_pag": result.raw_pag.model_dump(mode="json"),
        "constrained_pag": result.constrained_pag.model_dump(mode="json"),
        "delta": result.delta.model_dump(mode="json"),
    }


def test_deterministic_four_arm_context_is_canonical_and_background_valid() -> None:
    frame = deterministic_context_scm(n_per_arm=250, seed=404)
    table, rows = _jci_table_and_rows(frame)
    config = _config()

    assert tuple(frame.columns) == ("c.arm", "x.target_feature", "y.secure_functional")
    assert tuple(sorted(frame["c.arm"].unique())) == (0, 1, 2, 3)
    assert np.array_equal(
        frame["x.target_feature"].to_numpy(dtype=np.int64),
        (frame["c.arm"].to_numpy(dtype=np.int64) == 0).astype(np.int64),
    )
    assert table.variables[0].states == tuple(role.value for role in _ARM_ROLES)
    assert tuple(sorted(set(matrix_for_exact_rows(table, rows)[:, 0].tolist()))) == (0, 1, 2, 3)

    first = analyze_jci_stratum(table, rows, config, runner=_RealCausalLearnRunner())
    second = analyze_jci_stratum(table, rows, config, runner=_RealCausalLearnRunner())

    assert _canonical(first) == _canonical(second)
    base, provenance = build_jci_background(table)
    validate_pag_against_background(first.raw_pag, base)
    validate_pag_against_background(
        first.constrained_pag,
        provenance.materialized_background_knowledge,
    )
    validate_jci_analysis_result(table, rows, config, first)
    validate_pag_against_background(second.raw_pag, base)
    validate_pag_against_background(
        second.constrained_pag,
        provenance.materialized_background_knowledge,
    )
    validate_jci_analysis_result(table, rows, config, second)
    assert first.raw_pag.run_kind is PAGRunKind.JCI_RAW
    assert first.constrained_pag.run_kind is PAGRunKind.JCI_CONSTRAINED
    assert first.delta.assumption_ids == provenance.assumption_ids
