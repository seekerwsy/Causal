"""Immutable Prompt-side hypothesis freeze before randomized confirmation."""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Literal

from secaware.causal.background import validate_pag_against_background
from secaware.causal.paths import enumerate_possible_prompt_paths
from secaware.config import FCIDiscoveryConfig
from secaware.errors import ErrorCode, SecAwareError
from secaware.io.run_store import RunStore
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.causal import (
    BackgroundKnowledgeRecord,
    CausalTableRecord,
    DiscoveryFailureReason,
    DiscoveryFailureRecord,
    ExpectedOperationContrast,
    FrozenHypothesisRecord,
    PAGRecord,
    PAGRunKind,
    PathSupportRecord,
)
from secaware.schema.features import FeatureFamily, FeatureOperation
from secaware.tsg.feature_catalog import (
    PROMPT_FEATURE_CATALOG_SHA256,
    FeatureSpec,
    prompt_feature_spec,
)


_FUTURE_STAGE_NAMES = frozenset(
    {
        "intervene",
        "confirm",
        "build-confirmation-variants",
        "randomize-confirmation",
        "generate-confirmation",
        "run-oracle-confirmation",
        "import-functional-outcomes",
        "analyze-jci",
        "analyze-rfci",
        "report",
        "effects",
        "jci",
        "rfci",
        "reporting",
    }
)
_FUTURE_STAGE_PREFIXES = (
    "build-confirmation-",
    "randomize-confirmation-",
    "generate-confirmation-",
    "run-oracle-confirmation-",
    "import-functional-outcomes-",
    "confirm-",
    "analyze-jci-",
    "analyze-rfci-",
    "report-",
    "effects-",
    "jci-",
    "rfci-",
    "reporting-",
)
_FUTURE_ARTIFACT_DIRECTORIES = ("interventions", "analysis", "reports")
_FUTURE_ARTIFACT_PREFIXES = {
    "generation": ("confirmation", "assignment"),
    "oracle": ("confirmation",),
}
_OUTCOME_ESTIMANDS = {
    "y.secure_functional": "y_secure_functional",
    "y.cwe_security": "y_cwe_secure",
}


@dataclass(frozen=True, slots=True)
class HypothesisFreezeResult:
    """In-memory result later published by the transactional M4B stage."""

    hypotheses: tuple[FrozenHypothesisRecord, ...]
    failures: tuple[DiscoveryFailureRecord, ...]
    freeze_batch_sha256: str


def _freeze_error(message: str) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.ANALYSIS_INVALID,
        stage="causal.freeze",
        message=message,
    )


def _is_future_stage_name(stage_name: str) -> bool:
    return stage_name in _FUTURE_STAGE_NAMES or any(
        stage_name.startswith(prefix) for prefix in _FUTURE_STAGE_PREFIXES
    )


def guard_no_future_confirmation_or_analysis(store: RunStore) -> None:
    """Fail closed if any M5/M6 manifest or artifact is already present."""
    try:
        if type(store) is not RunStore:
            raise ValueError
        manifest_dir = store.path(".stages")
        if manifest_dir.exists():
            for candidate in manifest_dir.iterdir():
                if candidate.is_file() and candidate.suffix == ".json":
                    stage_name = candidate.stem
                    if _is_future_stage_name(stage_name):
                        raise _freeze_error(
                            "future confirmation or analysis artifact already exists"
                        )
        for directory in _FUTURE_ARTIFACT_DIRECTORIES:
            root = store.path(directory)
            if root.exists() and any(item.is_file() for item in root.rglob("*")):
                raise _freeze_error("future confirmation or analysis artifact already exists")
        for directory, prefixes in _FUTURE_ARTIFACT_PREFIXES.items():
            root = store.path(directory)
            if not root.exists():
                continue
            for candidate in root.rglob("*"):
                if candidate.is_file() and candidate.name.casefold().startswith(prefixes):
                    raise _freeze_error("future confirmation or analysis artifact already exists")
    except (KeyboardInterrupt, SystemExit, SecAwareError):
        raise
    except Exception:
        raise _freeze_error("future confirmation or analysis guard failed closed") from None


def _expected_sign(
    family: FeatureFamily,
    operation: FeatureOperation,
) -> Literal["positive", "negative", "null", "two_sided"]:
    if family is FeatureFamily.SAFETY_CONTROL:
        return "positive" if operation is FeatureOperation.ADD else "negative"
    if family is FeatureFamily.PRESENTATION_CONTROL:
        return "null"
    return "two_sided"


def expected_operation_contrasts(
    spec: FeatureSpec,
    outcome_variable_id: str,
) -> tuple[ExpectedOperationContrast, ...]:
    """Materialize the complete reviewed operation/estimand contract."""
    try:
        trusted = prompt_feature_spec(spec.feature_id)
        if trusted != spec or not trusted.intervenable:
            raise ValueError
        estimand = _OUTCOME_ESTIMANDS[outcome_variable_id]
        operations = tuple(sorted(trusted.operations, key=lambda item: item.value))
        return tuple(
            ExpectedOperationContrast(
                operation=operation,
                outcome_estimand_id=estimand,
                expected_sign=_expected_sign(trusted.feature_family, operation),
            )
            for operation in operations
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _freeze_error("expected contrast contract failed validation") from None


def revalidate_frozen_hypothesis(hypothesis: FrozenHypothesisRecord) -> FrozenHypothesisRecord:
    """Reauthenticate one frozen record before any M5 consumer materializes targets."""
    try:
        checked = FrozenHypothesisRecord.model_validate(hypothesis)
        spec = prompt_feature_spec(checked.target_feature_id)
        expected = expected_operation_contrasts(spec, checked.outcome_variable_id)
        if (
            not spec.intervenable
            or spec.feature_family is not checked.feature_family
            or tuple(sorted(spec.operations, key=lambda item: item.value))
            != checked.permitted_operations
            or expected != checked.expected_contrasts
            or checked.catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
        ):
            raise ValueError
        return checked
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _freeze_error("frozen hypothesis failed revalidation") from None


def _validate_freeze_coordinates(
    *,
    reference_pag: PAGRecord,
    supports: tuple[PathSupportRecord, ...],
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    catalog_sha256: str,
    extractor_policy_sha256: str,
    frozen_at_utc: datetime,
) -> str:
    config_sha256 = canonical_sha256(config.model_dump(mode="json"))
    variable_ids = tuple(item.variable_id for item in table.variables)
    if (
        reference_pag.run_kind is not PAGRunKind.OBSERVATIONAL_REFERENCE
        or reference_pag.table_id != table.table_id
        or reference_pag.variable_ids != variable_ids
        or reference_pag.config_sha256 != config_sha256
        or reference_pag.background_knowledge_sha256 != knowledge.knowledge_sha256
        or knowledge.table_id != table.table_id
        or catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
        or type(extractor_policy_sha256) is not str
        or len(extractor_policy_sha256) != 64
        or any(character not in "0123456789abcdef" for character in extractor_policy_sha256)
        or frozen_at_utc.tzinfo is None
        or frozen_at_utc.utcoffset() != timedelta(0)
    ):
        raise ValueError
    validate_pag_against_background(reference_pag, knowledge)
    candidates = enumerate_possible_prompt_paths(
        reference_pag,
        max_path_length=config.max_path_length,
        max_candidate_paths=config.max_candidate_paths,
    )
    candidate_by_id = {item.path_id: item for item in candidates}
    path_ids = tuple(item.path.path_id for item in supports)
    if len(path_ids) != len(set(path_ids)) or set(path_ids) != set(candidate_by_id):
        raise ValueError
    for support in supports:
        if (
            support.table_id != table.table_id
            or support.reference_pag_id != reference_pag.pag_id
            or support.bootstrap_config_sha256 != config_sha256
            or support.support_denominator != config.bootstrap_samples
            or candidate_by_id.get(support.path.path_id) != support.path
        ):
            raise ValueError
    return config_sha256


def _semantic_content_for_support(
    *,
    support: PathSupportRecord,
    table: CausalTableRecord,
    reference_pag: PAGRecord,
    knowledge: BackgroundKnowledgeRecord,
    config_sha256: str,
    catalog_sha256: str,
    extractor_policy_sha256: str,
) -> dict[str, object]:
    target_variable = support.path.variable_ids[0]
    target_feature_id = target_variable.removeprefix("x.")
    spec = prompt_feature_spec(target_feature_id)
    outcome_variable_id = support.path.variable_ids[-1]
    if not spec.intervenable or outcome_variable_id not in _OUTCOME_ESTIMANDS:
        raise ValueError
    if spec.applicable_cwes and table.cwe not in spec.applicable_cwes:
        raise ValueError
    permitted_operations = tuple(sorted(spec.operations, key=lambda item: item.value))
    return {
        "target_feature_id": spec.feature_id,
        "feature_family": spec.feature_family,
        "permitted_operations": permitted_operations,
        "scope_id": table.scope_id,
        "cwe": table.cwe,
        "model_id": table.model_id,
        "outcome_variable_id": outcome_variable_id,
        "reference_pag_id": reference_pag.pag_id,
        "path": support.path,
        "support_numerator": support.support_numerator,
        "support_denominator": support.support_denominator,
        "table_sha256": table.table_sha256,
        "catalog_sha256": catalog_sha256,
        "extractor_policy_sha256": extractor_policy_sha256,
        "fci_config_sha256": config_sha256,
        "background_knowledge_sha256": knowledge.knowledge_sha256,
        "expected_contrasts": expected_operation_contrasts(spec, outcome_variable_id),
    }


def _freeze_batch_sha256(
    *,
    semantic_sha256: Sequence[str],
    table: CausalTableRecord,
    reference_pag: PAGRecord,
    knowledge: BackgroundKnowledgeRecord,
    config_sha256: str,
    catalog_sha256: str,
    extractor_policy_sha256: str,
) -> str:
    return canonical_sha256(
        {
            "schema_version": "1.0",
            "semantic_hypothesis_sha256": list(semantic_sha256),
            "table_id": table.table_id,
            "table_sha256": table.table_sha256,
            "reference_pag_id": reference_pag.pag_id,
            "catalog_sha256": catalog_sha256,
            "extractor_policy_sha256": extractor_policy_sha256,
            "fci_config_sha256": config_sha256,
            "background_knowledge_sha256": knowledge.knowledge_sha256,
        }
    )


def build_no_stable_hypothesis_failure(
    *,
    table: CausalTableRecord,
    reference_pag: PAGRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    catalog_sha256: str,
    extractor_policy_sha256: str,
) -> DiscoveryFailureRecord:
    """Build the exact deterministic terminal record for an empty stable set."""
    try:
        checked_table = CausalTableRecord.model_validate(table)
        checked_reference = PAGRecord.model_validate(reference_pag)
        checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
        checked_config = FCIDiscoveryConfig.model_validate(config)
        config_sha256 = canonical_sha256(checked_config.model_dump(mode="json"))
        if (
            checked_reference.table_id != checked_table.table_id
            or checked_reference.config_sha256 != config_sha256
            or checked_reference.background_knowledge_sha256 != checked_knowledge.knowledge_sha256
            or checked_knowledge.table_id != checked_table.table_id
            or catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
            or type(extractor_policy_sha256) is not str
            or len(extractor_policy_sha256) != 64
            or any(character not in "0123456789abcdef" for character in extractor_policy_sha256)
        ):
            raise ValueError
        batch_sha256 = _freeze_batch_sha256(
            semantic_sha256=(),
            table=checked_table,
            reference_pag=checked_reference,
            knowledge=checked_knowledge,
            config_sha256=config_sha256,
            catalog_sha256=catalog_sha256,
            extractor_policy_sha256=extractor_policy_sha256,
        )
        return DiscoveryFailureRecord.from_content(
            table_id=checked_table.table_id,
            scope_id=checked_table.scope_id,
            model_id=checked_table.model_id,
            reason_code=DiscoveryFailureReason.NO_STABLE_HYPOTHESIS,
            table_sha256=checked_table.table_sha256,
            fci_config_sha256=config_sha256,
            background_knowledge_sha256=checked_knowledge.knowledge_sha256,
            detail_sha256=canonical_sha256(
                {
                    "reason": DiscoveryFailureReason.NO_STABLE_HYPOTHESIS.value,
                    "reference_pag_id": checked_reference.pag_id,
                    "freeze_batch_sha256": batch_sha256,
                }
            ),
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _freeze_error("no-stable failure inputs failed validation") from None


def revalidate_frozen_hypothesis_batch(
    hypotheses: Sequence[FrozenHypothesisRecord],
    *,
    table: CausalTableRecord,
    reference_pag: PAGRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    catalog_sha256: str,
    extractor_policy_sha256: str,
) -> tuple[FrozenHypothesisRecord, ...]:
    """Authenticate the complete ordered JSONL batch and its derived digest."""
    try:
        checked = tuple(
            revalidate_frozen_hypothesis(FrozenHypothesisRecord.model_validate(item))
            for item in hypotheses
        )
        checked_table = CausalTableRecord.model_validate(table)
        checked_reference = PAGRecord.model_validate(reference_pag)
        checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
        checked_config = FCIDiscoveryConfig.model_validate(config)
        config_sha256 = canonical_sha256(checked_config.model_dump(mode="json"))
        variable_ids = tuple(item.variable_id for item in checked_table.variables)
        if (
            not checked
            or checked_reference.run_kind is not PAGRunKind.OBSERVATIONAL_REFERENCE
            or checked_reference.table_id != checked_table.table_id
            or checked_reference.variable_ids != variable_ids
            or checked_reference.config_sha256 != config_sha256
            or checked_reference.background_knowledge_sha256 != checked_knowledge.knowledge_sha256
            or checked_knowledge.table_id != checked_table.table_id
            or catalog_sha256 != PROMPT_FEATURE_CATALOG_SHA256
        ):
            raise ValueError
        validate_pag_against_background(checked_reference, checked_knowledge)
        ordered = tuple(
            sorted(
                checked,
                key=lambda item: (
                    item.path.variable_ids,
                    tuple((left.value, right.value) for left, right in item.path.endpoint_marks),
                ),
            )
        )
        if ordered != checked or len({item.hypothesis_id for item in checked}) != len(checked):
            raise ValueError
        for item in checked:
            if (
                item.scope_id != checked_table.scope_id
                or item.cwe != checked_table.cwe
                or item.model_id != checked_table.model_id
                or item.table_sha256 != checked_table.table_sha256
                or item.reference_pag_id != checked_reference.pag_id
                or item.background_knowledge_sha256 != checked_knowledge.knowledge_sha256
                or item.fci_config_sha256 != config_sha256
                or item.catalog_sha256 != catalog_sha256
                or item.extractor_policy_sha256 != extractor_policy_sha256
            ):
                raise ValueError
        batch_sha256 = _freeze_batch_sha256(
            semantic_sha256=tuple(item.hypothesis_sha256 for item in checked),
            table=checked_table,
            reference_pag=checked_reference,
            knowledge=checked_knowledge,
            config_sha256=config_sha256,
            catalog_sha256=catalog_sha256,
            extractor_policy_sha256=extractor_policy_sha256,
        )
        if any(item.freeze_batch_sha256 != batch_sha256 for item in checked):
            raise ValueError
        return checked
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _freeze_error("frozen hypothesis batch failed revalidation") from None


def freeze_hypotheses(
    *,
    reference_pag: PAGRecord,
    path_supports: Sequence[PathSupportRecord],
    table: CausalTableRecord,
    knowledge: BackgroundKnowledgeRecord,
    config: FCIDiscoveryConfig,
    catalog_sha256: str,
    extractor_policy_sha256: str,
    store: RunStore,
    frozen_at_utc: datetime | None = None,
) -> HypothesisFreezeResult:
    """Freeze every stable discovery-only hypothesis without ranking or top-k."""
    guard_no_future_confirmation_or_analysis(store)
    try:
        checked_reference = PAGRecord.model_validate(reference_pag)
        checked_supports = tuple(PathSupportRecord.model_validate(item) for item in path_supports)
        checked_table = CausalTableRecord.model_validate(table)
        checked_knowledge = BackgroundKnowledgeRecord.model_validate(knowledge)
        checked_config = FCIDiscoveryConfig.model_validate(config)
        timestamp = frozen_at_utc or datetime.now(timezone.utc)
        config_sha256 = _validate_freeze_coordinates(
            reference_pag=checked_reference,
            supports=checked_supports,
            table=checked_table,
            knowledge=checked_knowledge,
            config=checked_config,
            catalog_sha256=catalog_sha256,
            extractor_policy_sha256=extractor_policy_sha256,
            frozen_at_utc=timestamp,
        )
        threshold = Decimal(str(checked_config.stability_threshold))
        stable = tuple(
            sorted(
                (
                    support
                    for support in checked_supports
                    if Decimal(support.support_numerator)
                    >= threshold * Decimal(support.support_denominator)
                ),
                key=lambda item: (
                    item.path.variable_ids,
                    tuple((left.value, right.value) for left, right in item.path.endpoint_marks),
                ),
            )
        )
        semantic_contents = tuple(
            _semantic_content_for_support(
                support=support,
                table=checked_table,
                reference_pag=checked_reference,
                knowledge=checked_knowledge,
                config_sha256=config_sha256,
                catalog_sha256=catalog_sha256,
                extractor_policy_sha256=extractor_policy_sha256,
            )
            for support in stable
        )
        semantic_sha256 = tuple(
            FrozenHypothesisRecord.semantic_sha256_from_content(content)
            for content in semantic_contents
        )
        if len(semantic_sha256) != len(set(semantic_sha256)):
            raise ValueError
        batch_sha256 = _freeze_batch_sha256(
            semantic_sha256=semantic_sha256,
            table=checked_table,
            reference_pag=checked_reference,
            knowledge=checked_knowledge,
            config_sha256=config_sha256,
            catalog_sha256=catalog_sha256,
            extractor_policy_sha256=extractor_policy_sha256,
        )
        hypotheses = tuple(
            FrozenHypothesisRecord.from_content(
                **content,
                freeze_batch_sha256=batch_sha256,
                frozen_at_utc=timestamp,
            )
            for content in semantic_contents
        )
        if hypotheses:
            revalidate_frozen_hypothesis_batch(
                hypotheses,
                table=checked_table,
                reference_pag=checked_reference,
                knowledge=checked_knowledge,
                config=checked_config,
                catalog_sha256=catalog_sha256,
                extractor_policy_sha256=extractor_policy_sha256,
            )
        failures: tuple[DiscoveryFailureRecord, ...] = ()
        if not hypotheses:
            failures = (
                build_no_stable_hypothesis_failure(
                    table=checked_table,
                    reference_pag=checked_reference,
                    knowledge=checked_knowledge,
                    config=checked_config,
                    catalog_sha256=catalog_sha256,
                    extractor_policy_sha256=extractor_policy_sha256,
                ),
            )
        return HypothesisFreezeResult(
            hypotheses=hypotheses,
            failures=failures,
            freeze_batch_sha256=batch_sha256,
        )
    except (KeyboardInterrupt, SystemExit):
        raise
    except Exception:
        raise _freeze_error("freeze inputs failed validation") from None


__all__ = [
    "HypothesisFreezeResult",
    "build_no_stable_hypothesis_failure",
    "expected_operation_contrasts",
    "freeze_hypotheses",
    "guard_no_future_confirmation_or_analysis",
    "revalidate_frozen_hypothesis",
    "revalidate_frozen_hypothesis_batch",
]
