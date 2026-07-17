from __future__ import annotations

from collections.abc import Callable

import numpy as np
import pandas as pd
import pytest

from secaware.causal.background import build_background_knowledge, validate_pag_against_background
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import RFCIConfig
from secaware.schema.causal import (
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    PAGRunKind,
)
from tests.synthetic.scm_fixtures import (
    latent_confounding_scm,
    null_factor_scm,
    true_chain_scm,
)


_TRUE_CHAIN_COLUMNS = {
    "x.feature": "x.safety.sql_parameterization",
    "x.prompt_motif": "x.motif.user_string_to_sql_without_parameterization",
    "y.secure_functional": "y.secure_functional",
}
_LATENT_COLUMNS = {
    "x.feature": "x.safety.sql_parameterization",
    "x.peer": "x.motif.user_string_to_sql_without_parameterization",
}
_NULL_COLUMNS = {
    "x.null": "x.presentation.noop_rewrite",
    "y.secure_functional": "y.secure_functional",
}


class _Node:
    def __init__(self, name: str) -> None:
        self._name = name

    def get_name(self) -> str:
        return self._name


class _EmptyGraph:
    def __init__(self, variable_ids: tuple[str, ...]) -> None:
        self._nodes = [_Node(variable_id) for variable_id in variable_ids]

    def get_nodes(self) -> list[_Node]:
        return self._nodes

    def get_graph_edges(self) -> list[object]:
        return []


class _FakeTetradSearch:
    instances: list["_FakeTetradSearch"] = []

    def __init__(self, frame: pd.DataFrame) -> None:
        self.frame = frame
        self.alpha: float | None = None
        self.tiers: list[tuple[int, str]] = []
        self.forbidden_directions: list[tuple[str, str]] = []
        self.rfci_kwargs: dict[str, object] | None = None
        type(self).instances.append(self)

    def use_g_square(self, *, alpha: float) -> None:
        self.alpha = alpha

    def add_to_tier(self, tier: int, variable_id: str) -> None:
        self.tiers.append((tier, variable_id))

    def set_forbidden(self, source: str, target: str) -> None:
        self.forbidden_directions.append((source, target))

    def run_rfci(self, **kwargs: object) -> None:
        self.rfci_kwargs = kwargs

    def get_causal_learn(self) -> _EmptyGraph:
        return _EmptyGraph(tuple(str(item) for item in self.frame.columns))


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


def _table_and_rows(
    frame: pd.DataFrame,
    columns: dict[str, str],
) -> tuple[CausalTableRecord, tuple[CausalObservationRecord, ...]]:
    ordered = tuple(sorted(columns.items(), key=lambda item: item[1]))
    variables = tuple(_variable(variable_id) for _source_name, variable_id in ordered)
    observations = []
    for index in range(len(frame)):
        task_id = f"synthetic-rfci-task-{index:05d}"
        prompt_id = f"synthetic-rfci-prompt-{index:05d}"
        values = tuple(int(frame.iloc[index][source_name]) for source_name, _variable_id in ordered)
        observations.append(
            (
                CausalObservationRecord.row_id_from_content(
                    task_id=task_id,
                    prompt_id=prompt_id,
                    model_id="synthetic-model",
                    seed_id=0,
                    values=values,
                ),
                task_id,
                prompt_id,
                0,
                values,
            )
        )
    table = CausalTableRecord.from_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="synthetic-model",
        variables=variables,
        row_count=len(observations),
        independent_task_count=len(observations),
        observation_payload=observations,
    )
    rows = tuple(
        sorted(
            (
                CausalObservationRecord.from_content(
                    table=table,
                    task_id=task_id,
                    prompt_id=prompt_id,
                    model_id=table.model_id,
                    seed_id=seed_id,
                    values=values,
                )
                for _row_id, task_id, prompt_id, seed_id, values in observations
            ),
            key=lambda item: (item.table_id, item.row_id),
        )
    )
    return table, rows


def _config() -> RFCIConfig:
    return RFCIConfig(
        enabled=True,
        alpha=0.01,
        depth=3,
        max_discriminating_path_length=4,
    )


@pytest.mark.parametrize(
    ("factory", "columns", "seed"),
    (
        (true_chain_scm, _TRUE_CHAIN_COLUMNS, 501),
        (latent_confounding_scm, _LATENT_COLUMNS, 502),
        (null_factor_scm, _NULL_COLUMNS, 503),
    ),
    ids=("true-chain", "latent-confounding", "null-factor"),
)
def test_fake_rfci_adapter_always_runs_for_observational_scm_families(
    factory: Callable[[int, int], pd.DataFrame],
    columns: dict[str, str],
    seed: int,
) -> None:
    from secaware.discovery import rfci_backend

    table, rows = _table_and_rows(factory(400, seed), columns)
    knowledge = build_background_knowledge(table)
    config = _config()
    _FakeTetradSearch.instances.clear()
    checked_table, matrix = rfci_backend._authenticated_rfci_matrix(table, rows)

    pag = rfci_backend._run_rfci_adapter(
        checked_table,
        matrix,
        knowledge,
        config,
        _FakeTetradSearch,
    )

    assert len(_FakeTetradSearch.instances) == 1
    search = _FakeTetradSearch.instances[0]
    assert tuple(search.frame.columns) == tuple(item.variable_id for item in table.variables)
    assert search.frame.to_numpy(dtype=np.int64).tobytes(order="C") == matrix.tobytes(order="C")
    assert search.alpha == config.alpha
    assert set(search.tiers) == {(tier, variable_id) for variable_id, tier in knowledge.tiers}
    assert set(search.forbidden_directions) == set(
        rfci_backend.expanded_forbidden_directions(knowledge)
    )
    assert search.rfci_kwargs == {
        "depth": config.depth,
        "stable_fas": True,
        "max_disc_path_length": config.max_discriminating_path_length,
        "complete_rule_set_used": True,
    }
    assert pag.run_kind is PAGRunKind.RFCI_SENSITIVITY
    assert pag.backend == rfci_backend.RFCI_BACKEND
    validate_pag_against_background(pag, knowledge)


def test_explicit_test_rfci_adapter_cannot_be_mistaken_for_production() -> None:
    from secaware.discovery import rfci_backend

    table, rows = _table_and_rows(true_chain_scm(200, 504), _TRUE_CHAIN_COLUMNS)

    pag = rfci_backend._run_test_rfci_adapter(table, rows, _config())

    assert pag.run_kind is PAGRunKind.RFCI_SENSITIVITY
    assert pag.backend == "test_rfci_fake_v1"
    assert pag.backend != rfci_backend.RFCI_BACKEND


def test_real_rfci_sensitivity_runs_only_when_optional_capability_is_available() -> None:
    from secaware.discovery.rfci_backend import (
        detect_rfci_capability,
        run_rfci_sensitivity,
        validate_rfci_sensitivity_result,
    )

    config = _config()
    capability = detect_rfci_capability(config)
    if capability.status == "unavailable":
        assert capability.available is False
        pytest.skip(f"optional RFCI unavailable: {capability.reason_code}")
    assert capability.status == "available"
    assert capability.available is True
    table, rows = _table_and_rows(true_chain_scm(1000, 505), _TRUE_CHAIN_COLUMNS)
    knowledge = build_background_knowledge(table)

    result = run_rfci_sensitivity(table, rows, knowledge, config)

    assert result.capability == capability
    assert result.pag is not None
    assert result.pag.run_kind is PAGRunKind.RFCI_SENSITIVITY
    validate_pag_against_background(result.pag, knowledge)
    assert validate_rfci_sensitivity_result(result, table, knowledge, config) == result
