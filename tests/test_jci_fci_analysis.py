from __future__ import annotations

from dataclasses import FrozenInstanceError
from typing import Any

import numpy as np
import pytest

from secaware.causal.background import validate_pag_against_background
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import FCIDiscoveryConfig
from secaware.errors import SecAwareError
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    CausalVariableSpec,
    EndpointMark,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
    VariableRole,
    jci_row_id_from_content,
)
from secaware.schema.experiments import ArmRole
from secaware.schema.outcomes import JCIObservationRecord


def _variable(variable_id: str) -> CausalVariableSpec:
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


def _jci_table_and_rows() -> tuple[CausalTableRecord, tuple[JCIObservationRecord, ...]]:
    roles = (ArmRole.TARGET_PATCH, ArmRole.NOOP_REWRITE)
    variables = (
        CausalVariableSpec(
            schema_version="1.0",
            variable_id="c.arm",
            role=VariableRole.C,
            states=tuple(role.value for role in roles),
            source_query_id="assignment.arm_role.v1",
            scope_id="scope.cwe_89",
            temporal_tier=0,
            adjacency_type="jci_context",
            producer_sha256="a" * 64,
        ),
        _variable("x.safety.sql_parameterization"),
        _variable("y.secure_functional"),
    )
    target_spec_id = "target_" + "1" * 64
    arm_protocol_id = "arm_protocol_" + "2" * 64
    payload = []
    for task_index in range(2):
        task_id = f"task-{task_index}"
        target_instance_id = f"target_instance_{task_index + 3:064x}"
        protocol_instance_id = f"protocol_instance_{task_index + 5:064x}"
        for arm_index in range(2):
            assignment_id = f"assignment_{task_index * 2 + arm_index + 7:064x}"
            values = (arm_index, task_index % 2, (task_index + arm_index) % 2)
            row_id = jci_row_id_from_content(
                assignment_id=assignment_id,
                task_id=task_id,
                target_spec_id=target_spec_id,
                target_instance_id=target_instance_id,
                arm_protocol_id=arm_protocol_id,
                protocol_instance_id=protocol_instance_id,
                values=values,
            )
            payload.append(
                (
                    row_id,
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
        model_id="model-a",
        variables=variables,
        independent_task_count=2,
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
        min_independent_tasks=2,
    )


class _CapturingRunner:
    def __init__(self, *, fail_on: PAGRunKind | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self.fail_on = fail_on

    def run(
        self,
        matrix: np.ndarray,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        self.calls.append(
            {
                "matrix_bytes": matrix.tobytes(order="C"),
                "matrix_shape": matrix.shape,
                "matrix_dtype": matrix.dtype.str,
                "matrix_writeable": matrix.flags.writeable,
                "table_id": table.table_id,
                "variable_ids": tuple(item.variable_id for item in table.variables),
                "config": config.model_dump(mode="json"),
                "backend_version": config.backend_version,
                "knowledge": knowledge,
                "run_kind": run_kind,
            }
        )
        if run_kind is self.fail_on:
            raise TimeoutError("injected timeout")
        edge = PAGEdgeRecord(
            left="c.arm",
            right="x.safety.sql_parameterization",
            left_mark=(
                EndpointMark.CIRCLE if run_kind is PAGRunKind.JCI_RAW else EndpointMark.TAIL
            ),
            right_mark=(
                EndpointMark.CIRCLE if run_kind is PAGRunKind.JCI_RAW else EndpointMark.ARROW
            ),
        )
        return PAGRecord.from_content(
            run_kind=run_kind,
            table_id=table.table_id,
            backend=config.backend,
            backend_version=config.backend_version,
            ci_test=config.ci_test,
            config_sha256=canonical_sha256(config.model_dump(mode="json")),
            background_knowledge_sha256=knowledge.knowledge_sha256,
            variable_ids=tuple(item.variable_id for item in table.variables),
            edges=(edge,),
        )


def test_raw_and_constrained_runs_use_identical_exact_data_and_distinct_bk() -> None:
    from secaware.causal.jci import analyze_jci_stratum

    table, rows = _jci_table_and_rows()
    runner = _CapturingRunner()

    result = analyze_jci_stratum(table, rows, _config(), runner=runner)

    assert result.raw_pag.run_kind is PAGRunKind.JCI_RAW
    assert result.constrained_pag.run_kind is PAGRunKind.JCI_CONSTRAINED
    assert result.raw_pag.table_id == result.constrained_pag.table_id == table.table_id
    assert result.raw_pag.background_knowledge_sha256 != (
        result.constrained_pag.background_knowledge_sha256
    )
    assert len(runner.calls) == 2
    raw_call, constrained_call = runner.calls
    for key in (
        "matrix_bytes",
        "matrix_shape",
        "matrix_dtype",
        "matrix_writeable",
        "table_id",
        "variable_ids",
        "config",
        "backend_version",
    ):
        assert raw_call[key] == constrained_call[key]
    assert raw_call["matrix_writeable"] is False
    assert raw_call["matrix_bytes"] == np.asarray(
        tuple(row.values for row in rows), dtype=np.int64
    ).tobytes(order="C")
    assert raw_call["knowledge"].unconstrained_variable_ids == ("c.arm",)
    assert all("c.arm" not in pair for pair in raw_call["knowledge"].forbidden_directions)
    assert constrained_call["knowledge"].knowledge_sha256 == (
        result.constrained_pag.background_knowledge_sha256
    )
    validate_pag_against_background(result.raw_pag, raw_call["knowledge"])
    validate_pag_against_background(result.constrained_pag, constrained_call["knowledge"])


def test_jci_analysis_is_deterministic_and_result_is_frozen() -> None:
    from secaware.causal.jci import analyze_jci_stratum

    table, rows = _jci_table_and_rows()
    first = analyze_jci_stratum(table, rows, _config(), runner=_CapturingRunner())
    second = analyze_jci_stratum(table, rows, _config(), runner=_CapturingRunner())

    assert first == second
    with pytest.raises((FrozenInstanceError, AttributeError)):
        first.raw_pag = second.constrained_pag  # type: ignore[misc]


@pytest.mark.parametrize("fail_on", (PAGRunKind.JCI_RAW, PAGRunKind.JCI_CONSTRAINED))
def test_jci_analysis_fails_closed_when_either_fci_run_fails(fail_on: PAGRunKind) -> None:
    from secaware.causal.jci import analyze_jci_stratum

    table, rows = _jci_table_and_rows()
    runner = _CapturingRunner(fail_on=fail_on)

    with pytest.raises(SecAwareError, match="JCI"):
        analyze_jci_stratum(table, rows, _config(), runner=runner)
    assert [call["run_kind"] for call in runner.calls] == (
        [PAGRunKind.JCI_RAW]
        if fail_on is PAGRunKind.JCI_RAW
        else [PAGRunKind.JCI_RAW, PAGRunKind.JCI_CONSTRAINED]
    )


def test_jci_analysis_rejects_noncanonical_or_nonexact_rows_before_runner() -> None:
    from secaware.causal.jci import analyze_jci_stratum

    table, rows = _jci_table_and_rows()
    runner = _CapturingRunner()

    with pytest.raises(SecAwareError, match="JCI"):
        analyze_jci_stratum(table, tuple(reversed(rows)), _config(), runner=runner)
    assert runner.calls == []


def test_jci_analysis_revalidates_runner_pag_provenance() -> None:
    from secaware.causal.jci import analyze_jci_stratum

    table, rows = _jci_table_and_rows()

    class _WrongRunKind(_CapturingRunner):
        def run(self, *args: Any, **kwargs: Any) -> PAGRecord:
            pag = super().run(*args, **kwargs)
            run_kind = kwargs.get("run_kind", args[4])
            if run_kind is PAGRunKind.JCI_RAW:
                return PAGRecord.from_content(
                    **{
                        **pag.model_dump(mode="python", exclude={"pag_id", "run_kind"}),
                        "run_kind": PAGRunKind.JCI_CONSTRAINED,
                    }
                )
            return pag

    with pytest.raises(SecAwareError, match="JCI"):
        analyze_jci_stratum(table, rows, _config(), runner=_WrongRunKind())


def test_persisted_jci_result_relation_recomputes_delta_and_rejects_forgery() -> None:
    from secaware.causal.jci import (
        JCIAnalysisResult,
        analyze_jci_stratum,
        validate_jci_analysis_result,
    )
    from secaware.schema.outcomes import JCIOrientationDeltaRecord

    table, rows = _jci_table_and_rows()
    config = _config()
    result = analyze_jci_stratum(table, rows, config, runner=_CapturingRunner())
    validate_jci_analysis_result(table, rows, config, result)

    forged_delta = JCIOrientationDeltaRecord.from_content(
        raw_pag_id=result.raw_pag.pag_id,
        constrained_pag_id=result.constrained_pag.pag_id,
        assumption_ids=result.delta.assumption_ids,
        changes=(),
    )
    forged = JCIAnalysisResult(
        raw_pag=result.raw_pag,
        constrained_pag=result.constrained_pag,
        delta=forged_delta,
    )
    with pytest.raises(SecAwareError, match="JCI"):
        validate_jci_analysis_result(table, rows, config, forged)
