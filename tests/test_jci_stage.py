from __future__ import annotations

from importlib import import_module
from pathlib import Path
from types import SimpleNamespace

import pytest

from secaware.config import FCIDiscoveryConfig
from secaware.errors import SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.pipeline.artifact import canonical_sha256
from secaware.pipeline.stages.effects import EFFECT_STAGE_OUTPUTS, effects_stage
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    JCIBackgroundKnowledgeRecord,
    PAGRecord,
    PAGRunKind,
    VariableRole,
    jci_row_id_from_content,
)
from secaware.schema.outcomes import (
    AnalysisFailureReason,
    AnalysisFailureRecord,
    JCIObservationRecord,
    JCIOrientationDeltaRecord,
)
from test_effect_stage import _base_store
from test_stage_orchestration import _store


EXPECTED_JCI_OUTPUTS = (
    "analysis/jci_tables.jsonl",
    "analysis/jci_observations.jsonl",
    "analysis/jci_raw_pags.jsonl",
    "analysis/jci_background_knowledge.jsonl",
    "analysis/jci_constrained_pags.jsonl",
    "analysis/jci_orientation_deltas.jsonl",
    "analysis/jci_failures.jsonl",
)


class _EmptyFCIRunner:
    def __init__(self) -> None:
        self.calls = 0

    def run(
        self,
        _matrix,
        table: CausalTableRecord,
        knowledge: BackgroundKnowledgeRecord,
        config: FCIDiscoveryConfig,
        run_kind: PAGRunKind,
    ) -> PAGRecord:
        self.calls += 1
        return PAGRecord.from_content(
            run_kind=run_kind,
            table_id=table.table_id,
            backend=config.backend,
            backend_version=config.backend_version,
            ci_test=config.ci_test,
            config_sha256=canonical_sha256(config.model_dump(mode="json")),
            background_knowledge_sha256=knowledge.knowledge_sha256,
            variable_ids=tuple(item.variable_id for item in table.variables),
            edges=(),
        )


@pytest.fixture(scope="session")
def committed_jci_base(tmp_path_factory: pytest.TempPathFactory):
    config, store = _base_store(tmp_path_factory.mktemp("jci-stage-base"))
    effects_stage(config, store, force=True)
    effect_bytes = tuple(
        (store.root / relative).read_bytes() for relative, _ in EFFECT_STAGE_OUTPUTS
    )
    module = import_module("secaware.pipeline.stages.jci")
    runner = _EmptyFCIRunner()
    result = module.jci_stage(config, store, runner=runner, force=True)
    return config, store, result, runner, effect_bytes


def test_jci_stage_declares_exact_ordered_outputs() -> None:
    module = import_module("secaware.pipeline.stages.jci")

    assert tuple(path.as_posix() for path, _model in module.JCI_STAGE_OUTPUTS) == (
        EXPECTED_JCI_OUTPUTS
    )
    assert tuple(model for _path, model in module.JCI_STAGE_OUTPUTS) == (
        CausalTableRecord,
        JCIObservationRecord,
        PAGRecord,
        JCIBackgroundKnowledgeRecord,
        PAGRecord,
        JCIOrientationDeltaRecord,
        AnalysisFailureRecord,
    )


def test_jci_analysis_universe_excludes_frozen_protocol_without_committed_assignment() -> None:
    module = import_module("secaware.pipeline.stages.jci")
    assigned_protocol = SimpleNamespace(arm_protocol_id="arm_protocol_" + "1" * 64)
    excluded_protocol = SimpleNamespace(arm_protocol_id="arm_protocol_" + "0" * 64)
    assignments = (SimpleNamespace(arm_protocol_id=assigned_protocol.arm_protocol_id),)

    selected = module._assigned_protocol_universe(
        (assigned_protocol, excluded_protocol),
        assignments,
    )

    assert selected == (assigned_protocol,)


def test_jci_analysis_universe_rejects_dangling_assignment_protocol() -> None:
    module = import_module("secaware.pipeline.stages.jci")
    frozen_protocol = SimpleNamespace(arm_protocol_id="arm_protocol_" + "1" * 64)
    dangling_assignment = SimpleNamespace(arm_protocol_id="arm_protocol_" + "0" * 64)

    with pytest.raises(SecAwareError, match="assignment protocol universe"):
        module._assigned_protocol_universe(
            (frozen_protocol,),
            (dangling_assignment,),
        )


def test_run_store_enforces_exact_jci_output_contract(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store._validate_stage_output_contract("jci-confirmation", EXPECTED_JCI_OUTPUTS)

    with pytest.raises(SecAwareError, match="output contract"):
        store._validate_stage_output_contract(
            "jci-confirmation", tuple(reversed(EXPECTED_JCI_OUTPUTS))
        )


def test_jci_stage_publishes_complete_fake_runner_transaction_and_preserves_effects(
    committed_jci_base,
) -> None:
    _config, store, result, runner, effect_bytes = committed_jci_base
    models = (
        CausalTableRecord,
        JCIObservationRecord,
        PAGRecord,
        JCIBackgroundKnowledgeRecord,
        PAGRecord,
        JCIOrientationDeltaRecord,
        AnalysisFailureRecord,
    )
    groups = tuple(
        tuple(
            read_jsonl(
                store.root / relative,
                model,
                required=True,
                allow_empty=index >= 2,
            )
        )
        for index, (relative, model) in enumerate(zip(EXPECTED_JCI_OUTPUTS, models, strict=True))
    )

    assert groups[0] and groups[1]
    for table in groups[0]:
        local_rows = tuple(row for row in groups[1] if row.table_id == table.table_id)
        distinct_counts = tuple(
            len({row.values[index] for row in local_rows})
            for index, _variable in enumerate(table.variables)
        )
        assert any(
            count == 1 and variable.role in {VariableRole.W, VariableRole.X, VariableRole.Y}
            for variable, count in zip(table.variables, distinct_counts, strict=True)
        )
        assert any(
            count > 1 and variable.role in {VariableRole.C, VariableRole.X}
            for variable, count in zip(table.variables, distinct_counts, strict=True)
        )
    assert len(groups[2]) == len(groups[4]) == len(groups[5]) == len(groups[0])
    assert len(groups[3]) == len(groups[0])
    assert not groups[6]
    assert result.table_count == len(groups[0])
    assert runner.calls == 2 * len(groups[0])
    assert tuple((store.root / relative).read_bytes() for relative, _ in EFFECT_STAGE_OUTPUTS) == (
        effect_bytes
    )


@pytest.mark.parametrize("varying_column_count", (0, 1))
def test_jci_stage_types_fewer_than_two_varying_columns_as_degenerate_without_runner(
    committed_jci_base,
    monkeypatch: pytest.MonkeyPatch,
    varying_column_count: int,
) -> None:
    config, store, _result, _runner, _effect_bytes = committed_jci_base
    module = import_module("secaware.pipeline.stages.jci")
    original_build = module.build_jci_tables

    def build_degenerate(*args, **kwargs):
        tables, rows = original_build(*args, **kwargs)
        changed_tables = []
        changed_rows = []
        for table in tables:
            local = tuple(row for row in rows if row.table_id == table.table_id)
            context_index = next(
                index
                for index, variable in enumerate(table.variables)
                if variable.role is VariableRole.C
            )
            payload = []
            changed_values = {}
            for row in local:
                values = [0] * len(table.variables)
                if varying_column_count == 1:
                    values[context_index] = row.values[context_index]
                encoded = tuple(values)
                changed_values[row.assignment_id] = encoded
                payload.append(
                    (
                        jci_row_id_from_content(
                            assignment_id=row.assignment_id,
                            task_id=row.task_id,
                            target_spec_id=row.target_spec_id,
                            target_instance_id=row.target_instance_id,
                            arm_protocol_id=row.arm_protocol_id,
                            protocol_instance_id=row.protocol_instance_id,
                            values=encoded,
                        ),
                        row.assignment_id,
                        row.task_id,
                        row.target_spec_id,
                        row.target_instance_id,
                        row.arm_protocol_id,
                        row.protocol_instance_id,
                        encoded,
                    )
                )
            changed_table = CausalTableRecord.from_jci_content(
                scope_id=table.scope_id,
                cwe=table.cwe,
                model_id=table.model_id,
                variables=table.variables,
                independent_task_count=table.independent_task_count,
                observation_payload=payload,
            )
            changed_tables.append(changed_table)
            changed_rows.extend(
                JCIObservationRecord.from_content(
                    table_id=changed_table.table_id,
                    assignment_id=row.assignment_id,
                    task_id=row.task_id,
                    target_spec_id=row.target_spec_id,
                    target_instance_id=row.target_instance_id,
                    arm_protocol_id=row.arm_protocol_id,
                    protocol_instance_id=row.protocol_instance_id,
                    values=changed_values[row.assignment_id],
                )
                for row in local
            )
        return (
            tuple(
                sorted(
                    changed_tables, key=lambda item: (item.scope_id, item.model_id, item.table_id)
                )
            ),
            tuple(sorted(changed_rows, key=lambda item: (item.table_id, item.row_id))),
        )

    runner = _EmptyFCIRunner()
    try:
        with monkeypatch.context() as scoped:
            scoped.setattr(module, "build_jci_tables", build_degenerate)
            scoped.setattr(module, "validate_jci_table_bundle", lambda *args, **kwargs: None)
            scoped.setattr(module, "validate_jci_relations", lambda *args, **kwargs: None)
            result = module.jci_stage(config, store, runner=runner, force=True)
        failures = tuple(
            read_jsonl(
                store.root / "analysis/jci_failures.jsonl",
                AnalysisFailureRecord,
                required=True,
                allow_empty=False,
            )
        )
        assert result.failure_count == result.table_count == len(failures) == 1
        assert failures[0].reason_code is AnalysisFailureReason.DEGENERATE_GSQ_SUPPORT
        assert runner.calls == 0
    finally:
        module.jci_stage(config, store, runner=_EmptyFCIRunner(), force=True)
