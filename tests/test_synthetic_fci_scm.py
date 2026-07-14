from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import numpy as np
import pandas as pd

from secaware.causal.background import build_background_knowledge
from secaware.causal.bootstrap import (
    TaskClusterFCIBootstrapResult,
    run_task_cluster_fci_bootstrap,
)
from secaware.causal.freeze import freeze_hypotheses
from secaware.causal.paths import compute_bootstrap_path_support
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import AppConfig, FCIDiscoveryConfig
from secaware.discovery.causal_learn_backend import run_causal_learn_fci
from secaware.io.run_store import RunStore
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    EndpointMark,
    PAGRecord,
    PAGRunKind,
    PathSupportRecord,
    VariableRole,
)
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256
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
    # These are two observed Prompt X proxies in the same temporal tier. This fixture
    # gates latent-endpoint uncertainty only; typed X-to-Y BK is covered elsewhere.
    "x.feature": "x.safety.sql_parameterization",
    "x.peer": "x.motif.user_string_to_sql_without_parameterization",
}
_NULL_COLUMNS = {
    "x.null": "x.presentation.noop_rewrite",
    "y.secure_functional": "y.secure_functional",
}


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


def _variable(variable_id: str, scope_id: str) -> CausalVariableSpec:
    declaration = declaration_by_id(variable_id)
    return CausalVariableSpec(
        schema_version="1.0",
        variable_id=declaration.variable_id,
        role=declaration.role,
        states=declaration.states,
        source_query_id=declaration.query_id,
        scope_id=scope_id,
        temporal_tier=declaration.tier,
        adjacency_type=declaration.adjacency_type,
        producer_sha256=declaration_sha256(declaration),
    )


def _table_bundle(
    frame: pd.DataFrame,
    columns: dict[str, str],
) -> tuple[CausalTableRecord, tuple[CausalObservationRecord, ...]]:
    scope_id = "scope.cwe_89"
    ordered = tuple(sorted(columns.items(), key=lambda item: item[1]))
    variables = tuple(_variable(variable_id, scope_id) for _name, variable_id in ordered)
    coordinates = tuple(
        (
            f"synthetic-task-{index:05d}",
            f"synthetic-prompt-{index:05d}",
            0,
            tuple(int(frame.iloc[index][source_name]) for source_name, _variable_id in ordered),
        )
        for index in range(len(frame))
    )
    payload = tuple(
        (
            CausalObservationRecord.row_id_from_content(
                task_id=task_id,
                prompt_id=prompt_id,
                model_id="synthetic-model",
                seed_id=seed_id,
                values=values,
            ),
            task_id,
            prompt_id,
            seed_id,
            values,
        )
        for task_id, prompt_id, seed_id, values in coordinates
    )
    table = CausalTableRecord.from_content(
        scope_id=scope_id,
        cwe="CWE-89",
        model_id="synthetic-model",
        variables=variables,
        row_count=len(payload),
        independent_task_count=len(payload),
        observation_payload=payload,
    )
    rows = tuple(
        CausalObservationRecord.from_content(
            table=table,
            task_id=task_id,
            prompt_id=prompt_id,
            model_id=table.model_id,
            seed_id=seed_id,
            values=values,
        )
        for task_id, prompt_id, seed_id, values in coordinates
    )
    return table, rows


def _config() -> FCIDiscoveryConfig:
    return FCIDiscoveryConfig(
        alpha=0.01,
        depth=3,
        max_path_length=4,
        bootstrap_samples=6,
        stability_threshold=0.5,
        min_independent_tasks=20,
        timeout_seconds=120.0,
    )


def _bootstrap(
    frame: pd.DataFrame,
    columns: dict[str, str],
) -> tuple[
    CausalTableRecord,
    tuple[CausalObservationRecord, ...],
    BackgroundKnowledgeRecord,
    FCIDiscoveryConfig,
    TaskClusterFCIBootstrapResult,
    tuple[PathSupportRecord, ...],
]:
    table, rows = _table_bundle(frame, columns)
    knowledge = build_background_knowledge(table)
    config = _config()
    result = run_task_cluster_fci_bootstrap(
        table,
        rows,
        knowledge,
        config,
        global_seed=20260714,
        runner=_RealCausalLearnRunner(),
    )
    supports = compute_bootstrap_path_support(
        table=table,
        observations=rows,
        global_seed=20260714,
        knowledge=knowledge,
        config=config,
        reference_pag=result.reference_pag,
        bootstrap_draws=result.bootstrap_draws,
        bootstrap_pags=result.bootstrap_pags,
        bootstrap_failures=result.bootstrap_failures,
    )
    return table, rows, knowledge, config, result, supports


def _canonical_bundle(
    result: TaskClusterFCIBootstrapResult,
    supports: tuple[PathSupportRecord, ...],
) -> dict[str, object]:
    return {
        "reference_draw": result.reference_draw.model_dump(mode="json"),
        "reference_pag": result.reference_pag.model_dump(mode="json"),
        "draws": [item.model_dump(mode="json") for item in result.bootstrap_draws],
        "pags": [item.model_dump(mode="json") for item in result.bootstrap_pags],
        "failures": [item.model_dump(mode="json") for item in result.bootstrap_failures],
        "supports": [item.model_dump(mode="json") for item in supports],
    }


def _assert_complete_bootstrap(
    result: TaskClusterFCIBootstrapResult,
    supports: tuple[PathSupportRecord, ...],
    config: FCIDiscoveryConfig,
) -> None:
    assert len(result.bootstrap_pags) + len(result.bootstrap_failures) == config.bootstrap_samples
    assert all(item.support_denominator == config.bootstrap_samples for item in supports)


def _store(tmp_path: Path, name: str) -> RunStore:
    config = AppConfig.model_validate(
        {
            "run": {"name": name, "output_dir": str(tmp_path / name)},
            "data": {
                "prompts_path": str(tmp_path / "prompts.jsonl"),
                "prompt_attestations_path": str(tmp_path / "attestations.jsonl"),
            },
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            "intervention": {"executor": "deterministic"},
        }
    )
    store = RunStore(config)
    store.mkdirs()
    return store


def test_true_chain_recovers_stable_possible_x_z_y_path_with_real_fci(tmp_path: Path) -> None:
    frame = true_chain_scm(2500, 101)
    first = _bootstrap(frame, _TRUE_CHAIN_COLUMNS)
    second = _bootstrap(frame, _TRUE_CHAIN_COLUMNS)
    table, _rows, knowledge, config, result, supports = first

    _assert_complete_bootstrap(result, supports, config)
    _assert_complete_bootstrap(second[4], second[5], second[3])
    assert _canonical_bundle(result, supports) == _canonical_bundle(second[4], second[5])
    target_path = (
        "x.safety.sql_parameterization",
        "x.motif.user_string_to_sql_without_parameterization",
        "y.secure_functional",
    )
    stable = [
        item
        for item in supports
        if item.path.variable_ids == target_path
        and item.support_numerator / item.support_denominator >= config.stability_threshold
    ]
    assert stable
    frozen = freeze_hypotheses(
        reference_pag=result.reference_pag,
        path_supports=supports,
        table=table,
        knowledge=knowledge,
        config=config,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        extractor_policy_sha256="e" * 64,
        store=_store(tmp_path, "true-chain"),
        frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
    )
    assert any(item.path.variable_ids == target_path for item in frozen.hypotheses)


def test_latent_confounding_preserves_pag_uncertainty_with_real_fci() -> None:
    frame = latent_confounding_scm(2500, 202)
    table, rows = _table_bundle(frame, _LATENT_COLUMNS)
    knowledge = build_background_knowledge(table)
    config = _config()
    matrix = np.asarray(tuple(row.values for row in rows), dtype=np.int64)

    assert {item.role for item in table.variables} == {VariableRole.X}
    assert {item.temporal_tier for item in table.variables} == {1}

    first = run_causal_learn_fci(matrix, table, knowledge, config)
    second = run_causal_learn_fci(matrix, table, knowledge, config)

    assert first.model_dump(mode="json") == second.model_dump(mode="json")
    assert len(first.edges) == 1
    assert EndpointMark.CIRCLE in {
        first.edges[0].left_mark,
        first.edges[0].right_mark,
    }


def test_null_factor_freezes_no_hypothesis_and_is_canonical(tmp_path: Path) -> None:
    frame = null_factor_scm(2500, 303)
    first = _bootstrap(frame, _NULL_COLUMNS)
    second = _bootstrap(frame, _NULL_COLUMNS)
    table, _rows, knowledge, config, result, supports = first

    _assert_complete_bootstrap(result, supports, config)
    _assert_complete_bootstrap(second[4], second[5], second[3])
    assert _canonical_bundle(result, supports) == _canonical_bundle(second[4], second[5])
    frozen = freeze_hypotheses(
        reference_pag=result.reference_pag,
        path_supports=supports,
        table=table,
        knowledge=knowledge,
        config=config,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        extractor_policy_sha256="e" * 64,
        store=_store(tmp_path, "null-factor"),
        frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
    )
    assert frozen.hypotheses == ()
    assert tuple(item.reason_code.value for item in frozen.failures) == ("no_stable_hypothesis",)
