from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from pydantic import ValidationError

from secaware.causal.background import build_background_knowledge
from secaware.causal.variable_catalog import declaration_by_id, declaration_sha256
from secaware.config import AppConfig, FCIDiscoveryConfig
from secaware.errors import SecAwareError
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    CausalObservationRecord,
    CausalTableRecord,
    CausalVariableSpec,
    DiscoveryFailureReason,
    EndpointMark,
    PAGEdgeRecord,
    PAGRecord,
    PAGRunKind,
    PathPatternRecord,
    PathSupportRecord,
)
from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.tsg.feature_catalog import PROMPT_FEATURE_CATALOG_SHA256


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


def _bundle(
    target_variable: str = "x.safety.sql_parameterization",
    outcome_variable: str = "y.secure_functional",
    *,
    threshold: float = 0.8,
) -> tuple[CausalTableRecord, object, FCIDiscoveryConfig, PAGRecord, PathSupportRecord]:
    variables = (_variable(target_variable), _variable(outcome_variable))
    values = ((0, 0), (1, 1))
    observations = tuple(
        (
            CausalObservationRecord.row_id_from_content(
                task_id=f"task-{index}",
                prompt_id=f"prompt-{index}",
                model_id="model-a",
                seed_id=0,
                values=row,
            ),
            f"task-{index}",
            f"prompt-{index}",
            0,
            row,
        )
        for index, row in enumerate(values)
    )
    table = CausalTableRecord.from_content(
        scope_id="scope.cwe_89",
        cwe="CWE-89",
        model_id="model-a",
        variables=variables,
        row_count=2,
        independent_task_count=2,
        observation_payload=observations,
    )
    knowledge = build_background_knowledge(table)
    config = FCIDiscoveryConfig(
        min_independent_tasks=2,
        bootstrap_samples=5,
        stability_threshold=threshold,
    )
    edge = PAGEdgeRecord(
        left=target_variable,
        right=outcome_variable,
        left_mark=EndpointMark.TAIL,
        right_mark=EndpointMark.ARROW,
    )
    reference = PAGRecord.from_content(
        run_kind=PAGRunKind.OBSERVATIONAL_REFERENCE,
        table_id=table.table_id,
        backend=config.backend,
        backend_version=config.backend_version,
        ci_test=config.ci_test,
        config_sha256=canonical_sha256(config.model_dump(mode="json")),
        background_knowledge_sha256=knowledge.knowledge_sha256,
        variable_ids=tuple(item.variable_id for item in variables),
        edges=(edge,),
    )
    path = PathPatternRecord.from_content(
        variable_ids=(target_variable, outcome_variable),
        endpoint_marks=((EndpointMark.TAIL, EndpointMark.ARROW),),
    )
    support = PathSupportRecord.from_content(
        table_id=table.table_id,
        reference_pag_id=reference.pag_id,
        path=path,
        support_numerator=4,
        support_denominator=5,
        bootstrap_config_sha256=canonical_sha256(config.model_dump(mode="json")),
    )
    return table, knowledge, config, reference, support


def _store(tmp_path: Path) -> RunStore:
    config = AppConfig.model_validate(
        {
            "run": {"name": "freeze-test", "output_dir": str(tmp_path / "run")},
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


def _freeze(
    tmp_path: Path,
    *,
    target_variable: str = "x.safety.sql_parameterization",
    outcome_variable: str = "y.secure_functional",
    threshold: float = 0.8,
    clock: datetime | None = None,
):
    from secaware.causal.freeze import freeze_hypotheses

    table, knowledge, config, reference, support = _bundle(
        target_variable, outcome_variable, threshold=threshold
    )
    result = freeze_hypotheses(
        reference_pag=reference,
        path_supports=(support,),
        table=table,
        knowledge=knowledge,
        config=config,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        extractor_policy_sha256="e" * 64,
        store=_store(tmp_path),
        frozen_at_utc=clock or datetime(2026, 7, 14, tzinfo=timezone.utc),
    )
    return result, (table, knowledge, config, reference, support)


def test_threshold_is_inclusive_and_all_stable_paths_are_frozen(tmp_path: Path) -> None:
    result, _bundle_items = _freeze(tmp_path, threshold=0.8)

    assert len(result.hypotheses) == 1
    assert result.failures == ()
    hypothesis = result.hypotheses[0]
    assert hypothesis.support_numerator == 4
    assert hypothesis.support_denominator == 5
    assert hypothesis.target_feature_id == "safety.sql_parameterization"
    assert hypothesis.feature_family is FeatureFamily.SAFETY_CONTROL
    assert hypothesis.permitted_operations == (FeatureOperation.ADD, FeatureOperation.REMOVE)
    assert tuple(item.operation for item in hypothesis.expected_contrasts) == (
        FeatureOperation.ADD,
        FeatureOperation.REMOVE,
    )
    assert tuple(item.expected_sign for item in hypothesis.expected_contrasts) == (
        "positive",
        "negative",
    )


def test_m4b_hypothesis_digest_commits_current_feature_catalog(tmp_path: Path) -> None:
    from secaware.causal.freeze import revalidate_frozen_hypothesis

    result, _bundle_items = _freeze(tmp_path)
    hypothesis = result.hypotheses[0]
    content = hypothesis.model_dump(
        mode="python",
        exclude={"schema_version", "hypothesis_id", "hypothesis_sha256"},
    )
    content["catalog_sha256"] = "0" * 64
    stale = type(hypothesis).from_content(**content)

    assert stale.hypothesis_sha256 != hypothesis.hypothesis_sha256
    with pytest.raises(SecAwareError, match="frozen hypothesis failed revalidation"):
        revalidate_frozen_hypothesis(stale)


@pytest.mark.parametrize(
    ("target", "expected_family", "expected_signs"),
    (
        (
            "x.presentation.noop_rewrite",
            FeatureFamily.PRESENTATION_CONTROL,
            ("null", "null"),
        ),
        (
            "x.task.database_query",
            FeatureFamily.TASK_FUNCTION,
            ("two_sided", "two_sided"),
        ),
    ),
)
def test_expected_contrast_contract_is_family_specific(
    tmp_path: Path,
    target: str,
    expected_family: FeatureFamily,
    expected_signs: tuple[str, str],
) -> None:
    result, _bundle_items = _freeze(tmp_path, target_variable=target)

    hypothesis = result.hypotheses[0]
    assert hypothesis.feature_family is expected_family
    assert tuple(item.expected_sign for item in hypothesis.expected_contrasts) == expected_signs
    assert tuple(item.outcome_estimand_id for item in hypothesis.expected_contrasts) == (
        "y_secure_functional",
        "y_secure_functional",
    )


def test_cwe_outcome_maps_to_explicit_secure_indicator(tmp_path: Path) -> None:
    result, _bundle_items = _freeze(tmp_path, outcome_variable="y.cwe_security")

    assert {item.outcome_estimand_id for item in result.hypotheses[0].expected_contrasts} == {
        "y_cwe_secure"
    }


def test_hypothesis_and_batch_ids_ignore_clock_but_timestamp_is_utc_provenance(
    tmp_path: Path,
) -> None:
    first, _ = _freeze(tmp_path / "first", clock=datetime(2026, 7, 14, tzinfo=timezone.utc))
    second, _ = _freeze(
        tmp_path / "second",
        clock=datetime(2026, 7, 15, tzinfo=timezone.utc),
    )

    assert first.freeze_batch_sha256 == second.freeze_batch_sha256
    assert first.hypotheses[0].hypothesis_id == second.hypotheses[0].hypothesis_id
    assert first.hypotheses[0].hypothesis_sha256 == second.hypotheses[0].hypothesis_sha256
    assert first.hypotheses[0].frozen_at_utc != second.hypotheses[0].frozen_at_utc

    with pytest.raises(SecAwareError, match="freeze inputs failed validation"):
        _freeze(tmp_path / "naive", clock=datetime(2026, 7, 14))
    with pytest.raises(SecAwareError, match="freeze inputs failed validation"):
        _freeze(
            tmp_path / "offset",
            clock=datetime(2026, 7, 14, tzinfo=timezone(timedelta(hours=8))),
        )


def test_frozen_record_rejects_semantic_digest_and_operation_contrast_mutation(
    tmp_path: Path,
) -> None:
    result, _ = _freeze(tmp_path)
    record = result.hypotheses[0]
    payload = record.model_dump(mode="json")
    payload["target_feature_id"] = "safety.path_normalization"
    with pytest.raises(ValidationError, match="causal contract failed validation"):
        type(record).model_validate(payload)

    semantic = record.model_dump(
        mode="python",
        exclude={"hypothesis_id", "hypothesis_sha256"},
    )
    semantic["expected_contrasts"] = (
        record.expected_contrasts[0].model_copy(update={"expected_sign": "null"}),
        record.expected_contrasts[1],
    )
    with pytest.raises(ValidationError, match="causal contract failed validation"):
        type(record).from_content(**semantic)

    payload = record.model_dump(mode="json")
    payload["expected_contrasts"] = payload["expected_contrasts"][:-1]
    with pytest.raises(ValidationError, match="causal contract failed validation"):
        type(record).model_validate(payload)


def test_complete_batch_revalidation_rejects_derived_batch_digest_mutation(
    tmp_path: Path,
) -> None:
    from secaware.causal.freeze import revalidate_frozen_hypothesis_batch

    result, (table, knowledge, config, reference, _support) = _freeze(tmp_path)
    assert (
        revalidate_frozen_hypothesis_batch(
            result.hypotheses,
            table=table,
            reference_pag=reference,
            knowledge=knowledge,
            config=config,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            extractor_policy_sha256="e" * 64,
        )
        == result.hypotheses
    )

    payload = result.hypotheses[0].model_dump(mode="python")
    payload["freeze_batch_sha256"] = "f" * 64
    mutated = type(result.hypotheses[0]).model_validate(payload)
    with pytest.raises(SecAwareError, match="frozen hypothesis batch failed revalidation"):
        revalidate_frozen_hypothesis_batch(
            (mutated,),
            table=table,
            reference_pag=reference,
            knowledge=knowledge,
            config=config,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            extractor_policy_sha256="e" * 64,
        )


def test_duplicate_path_or_target_pair_is_rejected(tmp_path: Path) -> None:
    from secaware.causal.freeze import freeze_hypotheses

    _result, (table, knowledge, config, reference, support) = _freeze(tmp_path / "seed")
    with pytest.raises(SecAwareError, match="freeze inputs failed validation"):
        freeze_hypotheses(
            reference_pag=reference,
            path_supports=(support, deepcopy(support)),
            table=table,
            knowledge=knowledge,
            config=config,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            extractor_policy_sha256="e" * 64,
            store=_store(tmp_path / "duplicate"),
            frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
        )


def test_freeze_rejects_a_support_subset_of_reference_candidates(tmp_path: Path) -> None:
    from secaware.causal.freeze import freeze_hypotheses

    table, knowledge, config, reference, _support = _bundle()

    with pytest.raises(SecAwareError, match="freeze inputs failed validation"):
        freeze_hypotheses(
            reference_pag=reference,
            path_supports=(),
            table=table,
            knowledge=knowledge,
            config=config,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            extractor_policy_sha256="e" * 64,
            store=_store(tmp_path),
            frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
        )


@pytest.mark.parametrize(
    "future_path",
    (
        (".stages", "confirm.json"),
        (".stages", "analyze-jci.json"),
        ("interventions", "variants_frozen.jsonl"),
        ("analysis", "itt_effects.jsonl"),
        ("reports", "summary.md"),
    ),
)
def test_freeze_guard_rejects_any_m5_m6_manifest_or_artifact_before_output(
    tmp_path: Path,
    future_path: tuple[str, str],
) -> None:
    from secaware.causal.freeze import freeze_hypotheses

    table, knowledge, config, reference, support = _bundle()
    store = _store(tmp_path)
    candidate = store.path(*future_path)
    candidate.parent.mkdir(parents=True, exist_ok=True)
    candidate.write_text("future", encoding="utf-8")

    with pytest.raises(SecAwareError, match="future confirmation or analysis artifact"):
        freeze_hypotheses(
            reference_pag=reference,
            path_supports=(support,),
            table=table,
            knowledge=knowledge,
            config=config,
            catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
            extractor_policy_sha256="e" * 64,
            store=store,
            frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
        )


def test_no_stable_path_returns_empty_and_typed_terminal_failure(tmp_path: Path) -> None:
    from secaware.causal.freeze import freeze_hypotheses

    table, knowledge, config, reference, support = _bundle(threshold=0.81)
    result = freeze_hypotheses(
        reference_pag=reference,
        path_supports=(support,),
        table=table,
        knowledge=knowledge,
        config=config,
        catalog_sha256=PROMPT_FEATURE_CATALOG_SHA256,
        extractor_policy_sha256="e" * 64,
        store=_store(tmp_path),
        frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
    )

    assert result.hypotheses == ()
    assert len(result.failures) == 1
    assert result.failures[0].reason_code is DiscoveryFailureReason.NO_STABLE_HYPOTHESIS
    assert result.freeze_batch_sha256


def test_catalog_reference_pag_and_support_provenance_are_authenticated(tmp_path: Path) -> None:
    from secaware.causal.freeze import freeze_hypotheses

    table, knowledge, config, reference, support = _bundle()
    with pytest.raises(SecAwareError, match="freeze inputs failed validation"):
        freeze_hypotheses(
            reference_pag=reference,
            path_supports=(support,),
            table=table,
            knowledge=knowledge,
            config=config,
            catalog_sha256="0" * 64,
            extractor_policy_sha256="e" * 64,
            store=_store(tmp_path),
            frozen_at_utc=datetime(2026, 7, 14, tzinfo=timezone.utc),
        )
