"""Pre-registered randomized ITT estimates over semantic protocol groups."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import TypeVar

from pydantic import BaseModel

from secaware.analysis.cluster_bootstrap import linear_percentile, task_cluster_bootstrap
from secaware.analysis.contrasts import materialize_contrasts, validate_contrasts
from secaware.analysis.multiple_testing import bonferroni_percentile_quantiles
from secaware.config import AnalysisConfig
from secaware.pipeline.artifact import canonical_sha256
from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import (
    ArmRole,
    ConfirmationProtocolRecord,
    FunctionalOutcomeContractRecord,
)
from secaware.schema.features import FeatureFamily
from secaware.schema.outcomes import (
    AnalysisFailureReason,
    AnalysisFailureRecord,
    AnalysisStage,
    AssignmentEvaluability,
    AssignmentOutcomeRecord,
    ContrastSpecRecord,
    CWESecurityOutcome,
    EffectBootstrapDrawRecord,
    FunctionalOutcomeRecord,
    FunctionalOutcomeStatus,
    ITTEffectRecord,
)


_ModelT = TypeVar("_ModelT", bound=BaseModel)
_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)
MAX_ESTIMATOR_SAMPLED_ROW_ENTRIES = 5_000_000
MAX_ESTIMATOR_ARTIFACT_RECORDS = 125_000
MAX_ESTIMATOR_DRAW_RECORDS = 125_000
_RESERVED_OUTCOMES = frozenset(
    {
        "y_secure_functional",
        "y_cwe_secure",
        "y_cwe_insecure",
        "y_cwe_unknown",
        "y_oracle_evaluable",
        "y_parse_ok",
        "y_functional_ok",
    }
)


@dataclass(frozen=True, slots=True)
class ITTEstimationResult:
    effects: tuple[ITTEffectRecord, ...]
    draws: tuple[EffectBootstrapDrawRecord, ...]
    failures: tuple[AnalysisFailureRecord, ...]


def _itt_error(message: str = "ITT estimation failed validation") -> ValueError:
    return ValueError(message)


def _trusted_records(
    values: Iterable[_ModelT],
    model: type[_ModelT],
    key_field: str,
    *,
    allow_empty: bool,
) -> tuple[tuple[_ModelT, ...], dict[str, _ModelT]]:
    if isinstance(values, (str, bytes, Mapping)):
        raise _itt_error()
    records: list[_ModelT] = []
    by_key: dict[str, _ModelT] = {}
    try:
        for index, value in enumerate(values):
            if index >= 100_000 or type(value) is not model or not model_shape_is_intact(value):
                raise _itt_error()
            checked = model.model_validate(
                value.model_dump(mode="python", round_trip=True, warnings=False)
            )
            key = getattr(checked, key_field)
            if type(key) is not str or key in by_key:
                raise _itt_error()
            records.append(checked)
            by_key[key] = checked
        if not allow_empty and not records:
            raise _itt_error()
        return tuple(records), by_key
    except _FATAL:
        raise
    except ValueError:
        raise
    except Exception:
        raise _itt_error() from None


def risk_difference(
    rows: Sequence[AssignmentOutcomeRecord],
    treatment: ArmRole,
    control: ArmRole,
    value: Callable[[AssignmentOutcomeRecord], int],
) -> tuple[float, int, int]:
    """Difference in assignment-arm means without diagnostic filtering."""

    if (
        isinstance(rows, (str, bytes, Mapping))
        or type(treatment) is not ArmRole
        or type(control) is not ArmRole
        or treatment is control
        or not callable(value)
    ):
        raise _itt_error("insufficient contrast assignment support")
    treated: list[int] = []
    controls: list[int] = []
    try:
        for row in rows:
            if type(row) is not AssignmentOutcomeRecord:
                raise _itt_error("insufficient contrast assignment support")
            if row.arm_role is treatment:
                projected = value(row)
                if type(projected) is not int or projected not in {0, 1}:
                    raise _itt_error("contrast outcome projection failed validation")
                treated.append(projected)
            elif row.arm_role is control:
                projected = value(row)
                if type(projected) is not int or projected not in {0, 1}:
                    raise _itt_error("contrast outcome projection failed validation")
                controls.append(projected)
        if not treated or not controls:
            raise _itt_error("insufficient contrast assignment support")
        return (
            (sum(treated) / len(treated)) - (sum(controls) / len(controls)),
            len(treated),
            len(controls),
        )
    except _FATAL:
        raise


def _validated_config(config: AnalysisConfig) -> AnalysisConfig:
    if type(config) is not AnalysisConfig or not model_shape_is_intact(config):
        raise _itt_error()
    try:
        return AnalysisConfig.model_validate(
            config.model_dump(mode="python", round_trip=True, warnings=False)
        )
    except _FATAL:
        raise
    except Exception:
        raise _itt_error() from None


def _protocol_index(
    protocols: Iterable[ConfirmationProtocolRecord],
) -> tuple[tuple[ConfirmationProtocolRecord, ...], dict[str, ConfirmationProtocolRecord]]:
    trusted, by_id = _trusted_records(
        protocols,
        ConfirmationProtocolRecord,
        "arm_protocol_id",
        allow_empty=False,
    )
    return trusted, by_id


def _validate_assignment_relation(
    rows: tuple[AssignmentOutcomeRecord, ...],
    protocols: dict[str, ConfirmationProtocolRecord],
) -> None:
    if {row.arm_protocol_id for row in rows} != set(protocols):
        raise _itt_error()
    instance_pairs: dict[tuple[str, str, str, str, str], set[tuple[str, str]]] = {}
    arm_counts: dict[tuple[str, str, str, str, str], dict[ArmRole, int]] = {}
    pair_owners: dict[tuple[str, str], tuple[str, str, str, str]] = {}
    target_instance_owners: dict[str, tuple[str, str, str]] = {}
    protocol_instance_owners: dict[str, tuple[str, str, str]] = {}
    for row in rows:
        protocol = protocols.get(row.arm_protocol_id)
        if (
            protocol is None
            or row.hypothesis_id != protocol.hypothesis_id
            or row.target_spec_id != protocol.target_spec_id
            or row.arm_role not in protocol.arm_roles
        ):
            raise _itt_error()
        task_key = (
            row.hypothesis_id,
            row.target_spec_id,
            row.arm_protocol_id,
            row.model_id,
            row.task_id,
        )
        pair = (row.target_instance_id, row.protocol_instance_id)
        instance_pairs.setdefault(task_key, set()).add(pair)
        counts = arm_counts.setdefault(task_key, {})
        counts[row.arm_role] = counts.get(row.arm_role, 0) + 1
        target_owner = (row.task_id, row.hypothesis_id, row.target_spec_id)
        protocol_owner = (row.task_id, row.arm_protocol_id, row.target_instance_id)
        pair_owner = (
            row.task_id,
            row.hypothesis_id,
            row.target_spec_id,
            row.arm_protocol_id,
        )
        if target_instance_owners.setdefault(row.target_instance_id, target_owner) != target_owner:
            raise _itt_error("ITT instance ownership failed validation")
        if (
            protocol_instance_owners.setdefault(row.protocol_instance_id, protocol_owner)
            != protocol_owner
            or pair_owners.setdefault(pair, pair_owner) != pair_owner
        ):
            raise _itt_error("ITT instance ownership failed validation")
    if any(len(pairs) != 1 for pairs in instance_pairs.values()):
        raise _itt_error("ITT instance ownership failed validation")
    for task_key, counts in arm_counts.items():
        protocol = protocols[task_key[2]]
        if (
            set(counts) != set(protocol.arm_roles)
            or len(set(counts.values())) != 1
            or not counts
            or min(counts.values()) < 1
        ):
            raise _itt_error("ITT complete block failed validation")


def _validate_task_contract_semantics(
    protocol: ConfirmationProtocolRecord,
    contract: FunctionalOutcomeContractRecord,
) -> None:
    target_arms = tuple(arm for arm in protocol.arms if arm.role is ArmRole.TASK_TARGET)
    generic_arms = tuple(arm for arm in protocol.arms if arm.role is ArmRole.TASK_GENERIC_CONTROL)
    primary = tuple(
        contrast
        for contrast in protocol.contrasts
        if contrast.priority == "primary"
        and contrast.treatment_arm is ArmRole.TASK_TARGET
        and contrast.control_arm is ArmRole.TASK_NOOP
    )
    expected_sign = (
        contract.expected_add_sign
        if protocol.operation.value == "add"
        else contract.expected_remove_sign
    )
    if (
        len(target_arms) != 1
        or len(target_arms[0].allowed_delta.allowed_transitions) != 1
        or target_arms[0].allowed_delta.allowed_transitions[0].feature_id
        != contract.task_feature_id
        or len(primary) != 1
        or primary[0].outcome_id != contract.outcome_id
        or primary[0].expected_sign != expected_sign
    ):
        raise _itt_error("functional outcome relation failed validation")
    generic_feature_id = contract.generic_control_feature_id
    if generic_feature_id is None:
        if generic_arms:
            raise _itt_error("functional outcome relation failed validation")
    elif (
        len(generic_arms) != 1
        or len(generic_arms[0].allowed_delta.allowed_transitions) != 1
        or generic_arms[0].allowed_delta.allowed_transitions[0].feature_id != generic_feature_id
    ):
        raise _itt_error("functional outcome relation failed validation")


def _validate_functional_relation(
    rows: tuple[AssignmentOutcomeRecord, ...],
    protocols: dict[str, ConfirmationProtocolRecord],
    contracts: Iterable[FunctionalOutcomeContractRecord],
    functional_outcomes: Iterable[FunctionalOutcomeRecord],
) -> tuple[
    dict[str, bool],
    dict[str, FunctionalOutcomeContractRecord],
    dict[str, FunctionalOutcomeRecord],
]:
    contract_records, contract_by_id = _trusted_records(
        contracts,
        FunctionalOutcomeContractRecord,
        "contract_id",
        allow_empty=True,
    )
    outcome_records, outcome_by_assignment = _trusted_records(
        functional_outcomes,
        FunctionalOutcomeRecord,
        "assignment_id",
        allow_empty=True,
    )
    task_protocols = {
        protocol_id: protocol
        for protocol_id, protocol in protocols.items()
        if protocol.feature_family is FeatureFamily.TASK_FUNCTION
    }
    contracted_protocols = {
        protocol_id: protocol
        for protocol_id, protocol in task_protocols.items()
        if protocol.functional_outcome_contract_id is not None
    }
    expected_contract_ids = {
        protocol.functional_outcome_contract_id
        for protocol in contracted_protocols.values()
        if protocol.functional_outcome_contract_id is not None
    }
    if not task_protocols:
        if contract_records or outcome_records:
            raise _itt_error("functional outcome relation failed validation")
        return {protocol_id: True for protocol_id in protocols}, {}, {}
    if contract_records and set(contract_by_id) != expected_contract_ids:
        raise _itt_error("functional outcome relation failed validation")
    for protocol in contracted_protocols.values():
        contract_id = protocol.functional_outcome_contract_id
        contract = contract_by_id.get(contract_id or "")
        if contract is not None:
            _validate_task_contract_semantics(protocol, contract)
    support_by_protocol = {
        protocol_id: protocol_id not in contracted_protocols for protocol_id in protocols
    }
    if not outcome_records:
        return support_by_protocol, contract_by_id, {}
    if not contracted_protocols or not contract_records:
        raise _itt_error("functional outcome relation failed validation")
    task_rows = tuple(row for row in rows if row.arm_protocol_id in contracted_protocols)
    expected_assignments = {row.assignment_id for row in task_rows}
    if set(outcome_by_assignment) != expected_assignments:
        raise _itt_error("functional outcome relation failed validation")
    row_by_assignment = {row.assignment_id: row for row in task_rows}
    for assignment_id, outcome in outcome_by_assignment.items():
        row = row_by_assignment[assignment_id]
        protocol = contracted_protocols[row.arm_protocol_id]
        contract_id = protocol.functional_outcome_contract_id
        contract = contract_by_id.get(contract_id or "")
        if (
            contract is None
            or outcome.contract_id != contract.contract_id
            or outcome.evaluator_policy_sha256 != contract.evaluator_policy_sha256
        ):
            raise _itt_error("functional outcome relation failed validation")
    support_by_protocol.update({protocol_id: True for protocol_id in contracted_protocols})
    return support_by_protocol, contract_by_id, outcome_by_assignment


def _outcome_projection(
    protocol: ConfirmationProtocolRecord,
    contrast: ContrastSpecRecord,
    *,
    functional_supported: bool,
    contract_by_id: dict[str, FunctionalOutcomeContractRecord],
    functional_by_assignment: dict[str, FunctionalOutcomeRecord],
) -> tuple[
    Callable[[AssignmentOutcomeRecord], int],
    Callable[[AssignmentOutcomeRecord], bool],
    bool,
]:
    outcome_id = contrast.outcome_id
    if outcome_id == "y_secure_functional":
        return (
            lambda row: row.secure_functional_success,
            lambda row: (
                row.oracle_evaluability is AssignmentEvaluability.UNKNOWN_PARSE_FAILURE
                or row.functional_outcome_status is FunctionalOutcomeStatus.UNKNOWN
            ),
            False,
        )
    if outcome_id == "y_cwe_secure":
        return (
            lambda row: int(row.cwe_security_outcome is CWESecurityOutcome.SECURE),
            lambda row: row.oracle_evaluability is AssignmentEvaluability.UNKNOWN_PARSE_FAILURE,
            False,
        )
    if outcome_id == "y_cwe_insecure":
        return (
            lambda row: int(row.cwe_security_outcome is CWESecurityOutcome.INSECURE),
            lambda row: row.oracle_evaluability is AssignmentEvaluability.UNKNOWN_PARSE_FAILURE,
            False,
        )
    if outcome_id == "y_cwe_unknown":
        return (
            lambda row: int(row.cwe_security_outcome is CWESecurityOutcome.UNKNOWN),
            lambda _row: False,
            False,
        )
    if outcome_id == "y_oracle_evaluable":
        return (
            lambda row: int(row.oracle_evaluability is AssignmentEvaluability.EVALUABLE),
            lambda _row: False,
            False,
        )
    if outcome_id == "y_parse_ok":
        return lambda row: int(row.parse_ok), lambda _row: False, False
    if outcome_id == "y_functional_ok":
        return (
            lambda row: int(row.functional_ok),
            lambda row: row.functional_outcome_status is FunctionalOutcomeStatus.UNKNOWN,
            False,
        )

    contract_id = protocol.functional_outcome_contract_id
    contract = contract_by_id.get(contract_id or "")
    if (
        protocol.feature_family is not FeatureFamily.TASK_FUNCTION
        or outcome_id in _RESERVED_OUTCOMES
        or (contract is not None and contract.outcome_id != outcome_id)
    ):
        raise _itt_error("functional outcome projection failed validation")
    if not functional_supported:
        return lambda _row: 0, lambda _row: False, True
    if contract is None:
        raise _itt_error("functional outcome relation failed validation")

    def functional_value(row: AssignmentOutcomeRecord) -> int:
        outcome = functional_by_assignment.get(row.assignment_id)
        if outcome is None:
            raise _itt_error("functional outcome relation failed validation")
        return int(outcome.status is FunctionalOutcomeStatus.PASS)

    def functional_unknown(row: AssignmentOutcomeRecord) -> bool:
        outcome = functional_by_assignment.get(row.assignment_id)
        if outcome is None:
            raise _itt_error("functional outcome relation failed validation")
        return outcome.status is FunctionalOutcomeStatus.UNKNOWN

    return functional_value, functional_unknown, False


def _sensitivity_bounds(
    rows: tuple[AssignmentOutcomeRecord, ...],
    contrast: ContrastSpecRecord,
    observed: Callable[[AssignmentOutcomeRecord], int],
    unknown: Callable[[AssignmentOutcomeRecord], bool],
    point: float,
) -> tuple[float, float]:
    def best(row: AssignmentOutcomeRecord) -> int:
        if not unknown(row):
            return observed(row)
        return int(row.arm_role is contrast.treatment_arm)

    def worst(row: AssignmentOutcomeRecord) -> int:
        if not unknown(row):
            return observed(row)
        return int(row.arm_role is not contrast.treatment_arm)

    best_effect, _, _ = risk_difference(
        rows,
        contrast.treatment_arm,
        contrast.control_arm,
        best,
    )
    worst_effect, _, _ = risk_difference(
        rows,
        contrast.treatment_arm,
        contrast.control_arm,
        worst,
    )
    return min(point, best_effect, worst_effect), max(point, best_effect, worst_effect)


def _status(
    protocol: ConfirmationProtocolRecord,
    contrast: ContrastSpecRecord,
    *,
    ci_low: float,
    ci_high: float,
    functional_supported: bool,
) -> str:
    if protocol.feature_family is FeatureFamily.TASK_FUNCTION and not functional_supported:
        return "unsupported_missing_functional_outcome"
    if protocol.feature_family is FeatureFamily.PRESENTATION_CONTROL:
        return (
            "negative_control_consistent" if ci_low <= 0.0 <= ci_high else "negative_control_shift"
        )
    if contrast.expected_sign == "positive":
        if ci_low > 0.0:
            return "confirmed_expected_direction"
        if ci_high < 0.0:
            return "opposite_direction"
    elif contrast.expected_sign == "negative":
        if ci_high < 0.0:
            return "confirmed_expected_direction"
        if ci_low > 0.0:
            return "opposite_direction"
    elif contrast.expected_sign == "two_sided" and not ci_low <= 0.0 <= ci_high:
        return "confirmed_expected_direction"
    elif contrast.expected_sign == "null" and not ci_low <= 0.0 <= ci_high:
        return "opposite_direction"
    return "inconclusive"


def _analysis_config_payload(config: AnalysisConfig) -> dict[str, object]:
    return {
        "bootstrap_samples": config.bootstrap_samples,
        "percentile_method": config.percentile_method,
        "max_failed_bootstrap_fraction": config.max_failed_bootstrap_fraction,
        "ci_level": config.ci_level,
        "multiplicity_method": config.multiplicity_method,
        "min_independent_tasks": config.min_independent_tasks,
    }


def _assignment_universe_payload(
    semantic_key: tuple[str, str, str, str],
    rows: tuple[AssignmentOutcomeRecord, ...],
) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "semantic_group": list(semantic_key),
        "assignments": [
            {
                "assignment_id": row.assignment_id,
                "execution_status": row.execution_status.value,
                "secure_functional_success": row.secure_functional_success,
                "cwe_security_outcome": row.cwe_security_outcome.value,
                "oracle_evaluability": row.oracle_evaluability.value,
                "parse_ok": row.parse_ok,
                "functional_ok": row.functional_ok,
                **(
                    {"functional_outcome_status": row.functional_outcome_status.value}
                    if row.functional_outcome_status is not None
                    else {}
                ),
            }
            for row in rows
        ],
    }


def _functional_provenance_payload(
    protocol: ConfirmationProtocolRecord,
    rows: tuple[AssignmentOutcomeRecord, ...],
    functional_by_assignment: dict[str, FunctionalOutcomeRecord],
) -> dict[str, object]:
    contract_ids = (
        []
        if protocol.functional_outcome_contract_id is None
        else [protocol.functional_outcome_contract_id]
    )
    return {
        "contract_ids": sorted(contract_ids),
        "functional_outcome_ids": sorted(
            outcome.functional_outcome_id
            for row in rows
            if (outcome := functional_by_assignment.get(row.assignment_id)) is not None
        ),
    }


def _bootstrap_will_run(
    protocol: ConfirmationProtocolRecord,
    contrast: ContrastSpecRecord,
    support_by_protocol: dict[str, bool],
) -> bool:
    return not (
        protocol.feature_family is FeatureFamily.TASK_FUNCTION
        and contrast.outcome_id not in _RESERVED_OUTCOMES
        and not support_by_protocol[protocol.arm_protocol_id]
    )


def calculate_itt(
    outcomes: Iterable[AssignmentOutcomeRecord],
    analysis_config: AnalysisConfig,
    *,
    protocols: Iterable[ConfirmationProtocolRecord],
    contrasts: Iterable[ContrastSpecRecord] | None = None,
    functional_contracts: Iterable[FunctionalOutcomeContractRecord] = (),
    functional_outcomes: Iterable[FunctionalOutcomeRecord] = (),
) -> ITTEstimationResult:
    """Calculate effects, persisted bootstrap draws, and bounded analysis failures."""

    config = _validated_config(analysis_config)
    protocol_records, protocol_by_id = _protocol_index(protocols)
    frozen_contrasts = (
        materialize_contrasts(protocol_records)
        if contrasts is None
        else validate_contrasts(protocol_records, contrasts)
    )
    rows, _rows_by_assignment = _trusted_records(
        outcomes,
        AssignmentOutcomeRecord,
        "assignment_id",
        allow_empty=False,
    )
    _validate_assignment_relation(rows, protocol_by_id)
    support_by_protocol, contract_by_id, functional_by_assignment = _validate_functional_relation(
        rows,
        protocol_by_id,
        functional_contracts,
        functional_outcomes,
    )
    config_sha256 = canonical_sha256(
        {"schema_version": "1.0", "analysis_config": _analysis_config_payload(config)}
    )
    input_bundle_sha256 = canonical_sha256(
        {
            "schema_version": "1.0",
            "assignment_outcome_ids": sorted(row.outcome_id for row in rows),
            "protocol_ids": sorted(record.arm_protocol_id for record in protocol_records),
            "contrast_ids": sorted(record.contrast_id for record in frozen_contrasts),
            "functional_contract_ids": sorted(contract_by_id),
            "functional_outcome_ids": sorted(
                record.functional_outcome_id for record in functional_by_assignment.values()
            ),
        }
    )
    family_sizes: dict[str, int] = {}
    for contrast in frozen_contrasts:
        family_sizes[contrast.multiplicity_family_id] = (
            family_sizes.get(contrast.multiplicity_family_id, 0) + 1
        )
    contrasts_by_protocol: dict[str, list[ContrastSpecRecord]] = {}
    for contrast in frozen_contrasts:
        contrasts_by_protocol.setdefault(contrast.arm_protocol_id, []).append(contrast)
    semantic_rows: dict[
        tuple[str, str, str, str],
        list[AssignmentOutcomeRecord],
    ] = {}
    for row in rows:
        key = (
            row.hypothesis_id,
            row.target_spec_id,
            row.arm_protocol_id,
            row.model_id,
        )
        semantic_rows.setdefault(key, []).append(row)

    total_sampled_row_entries = 0
    total_artifact_records = 0
    total_draw_records = 0
    for semantic_key, grouped in semantic_rows.items():
        protocol = protocol_by_id[semantic_key[2]]
        total_artifact_records += len(contrasts_by_protocol[protocol.arm_protocol_id])
        runnable_contrasts = sum(
            _bootstrap_will_run(protocol, contrast, support_by_protocol)
            for contrast in contrasts_by_protocol[protocol.arm_protocol_id]
        )
        if len({row.task_id for row in grouped}) >= config.min_independent_tasks:
            total_draw_records += config.bootstrap_samples * runnable_contrasts
        total_sampled_row_entries += len(grouped) * config.bootstrap_samples * runnable_contrasts
    if total_sampled_row_entries > MAX_ESTIMATOR_SAMPLED_ROW_ENTRIES:
        raise _itt_error("ITT bootstrap work budget failed validation")
    if total_artifact_records > MAX_ESTIMATOR_ARTIFACT_RECORDS:
        raise _itt_error("ITT artifact budget failed validation")
    if total_draw_records > MAX_ESTIMATOR_DRAW_RECORDS:
        raise _itt_error("ITT draw artifact budget failed validation")

    effects: list[ITTEffectRecord] = []
    draws: list[EffectBootstrapDrawRecord] = []
    failures: list[AnalysisFailureRecord] = []
    for semantic_key in sorted(semantic_rows):
        hypothesis_id, target_spec_id, protocol_id, model_id = semantic_key
        protocol = protocol_by_id[protocol_id]
        group_rows = tuple(sorted(semantic_rows[semantic_key], key=lambda item: item.assignment_id))
        task_ids = tuple(sorted({row.task_id for row in group_rows}))
        if len(task_ids) < config.min_independent_tasks:
            for contrast in contrasts_by_protocol[protocol_id]:
                coordinate_sha256 = canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "effect_coordinate": [
                            *semantic_key,
                            contrast.contrast_id,
                            contrast.outcome_id,
                        ],
                    }
                )
                failures.append(
                    AnalysisFailureRecord.from_content(
                        stage=AnalysisStage.EFFECTS,
                        subject_id=f"effect_coordinate_{coordinate_sha256}",
                        reason_code=AnalysisFailureReason.INSUFFICIENT_SUPPORT,
                        config_sha256=config_sha256,
                        input_bundle_sha256=input_bundle_sha256,
                    )
                )
            continue
        assignment_universe_sha256 = canonical_sha256(
            _assignment_universe_payload(semantic_key, group_rows)
        )
        instance_universe = sorted(
            {(row.task_id, row.target_instance_id, row.protocol_instance_id) for row in group_rows}
        )
        target_instance_universe_sha256 = canonical_sha256(
            {
                "schema_version": "1.0",
                "semantic_group": list(semantic_key),
                "instances": [
                    {
                        "task_id": task_id,
                        "target_instance_id": target_instance_id,
                        "protocol_instance_id": protocol_instance_id,
                    }
                    for task_id, target_instance_id, protocol_instance_id in instance_universe
                ],
            }
        )
        functional_provenance = _functional_provenance_payload(
            protocol,
            group_rows,
            functional_by_assignment,
        )
        for contrast in contrasts_by_protocol[protocol_id]:
            observed, unknown, unsupported_custom = _outcome_projection(
                protocol,
                contrast,
                functional_supported=support_by_protocol[protocol_id],
                contract_by_id=contract_by_id,
                functional_by_assignment=functional_by_assignment,
            )
            point, treatment_n, control_n = risk_difference(
                group_rows,
                contrast.treatment_arm,
                contrast.control_arm,
                observed,
            )
            effect_group = (
                hypothesis_id,
                target_spec_id,
                protocol_id,
                model_id,
                contrast.contrast_id,
                contrast.outcome_id,
            )
            config_payload = _analysis_config_payload(config)
            if unsupported_custom:
                ci_low = ci_high = sensitivity_low = sensitivity_high = point = 0.0
                bootstrap_manifest_sha256 = canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "state": "unsupported-not-run",
                        "reason": "missing-functional-outcome",
                        "effect_group": list(effect_group),
                        "analysis_config": config_payload,
                        "functional_provenance": functional_provenance,
                        "assignment_universe_sha256": assignment_universe_sha256,
                        "target_instance_universe_sha256": (target_instance_universe_sha256),
                    }
                )
            else:
                sensitivity_low, sensitivity_high = _sensitivity_bounds(
                    group_rows,
                    contrast,
                    observed,
                    unknown,
                    point,
                )
                seed_material = bytes.fromhex(
                    canonical_sha256(
                        {
                            "schema_version": "1.0",
                            "bootstrap_seed_kind": "semantic-itt-v1",
                            "effect_group": list(effect_group),
                            "assignment_universe_sha256": assignment_universe_sha256,
                        }
                    )
                )
                try:
                    bootstrap = task_cluster_bootstrap(
                        group_rows,
                        lambda sampled: risk_difference(
                            sampled,
                            contrast.treatment_arm,
                            contrast.control_arm,
                            observed,
                        )[0],
                        samples=config.bootstrap_samples,
                        seed_material=seed_material,
                        max_failed_fraction=config.max_failed_bootstrap_fraction,
                    )
                except _FATAL:
                    raise
                except ValueError:
                    coordinate_sha256 = canonical_sha256(
                        {
                            "schema_version": "1.0",
                            "effect_coordinate": list(effect_group),
                        }
                    )
                    failures.append(
                        AnalysisFailureRecord.from_content(
                            stage=AnalysisStage.EFFECTS,
                            subject_id=f"effect_coordinate_{coordinate_sha256}",
                            reason_code=AnalysisFailureReason.BOOTSTRAP_FAILURE,
                            config_sha256=config_sha256,
                            input_bundle_sha256=input_bundle_sha256,
                        )
                    )
                    continue
                if (
                    bootstrap.failed_replicates != 0
                    or len(bootstrap.estimates) != config.bootstrap_samples
                    or len(bootstrap.task_draws) != config.bootstrap_samples
                    or any(
                        len(draw) != len(task_ids) or set(draw) - set(task_ids)
                        for draw in bootstrap.task_draws
                    )
                ):
                    coordinate_sha256 = canonical_sha256(
                        {
                            "schema_version": "1.0",
                            "effect_coordinate": list(effect_group),
                        }
                    )
                    failures.append(
                        AnalysisFailureRecord.from_content(
                            stage=AnalysisStage.EFFECTS,
                            subject_id=f"effect_coordinate_{coordinate_sha256}",
                            reason_code=AnalysisFailureReason.BOOTSTRAP_FAILURE,
                            config_sha256=config_sha256,
                            input_bundle_sha256=input_bundle_sha256,
                        )
                    )
                    continue
                low_q, high_q = bonferroni_percentile_quantiles(
                    confidence_level=config.ci_level,
                    number_of_pre_registered_contrasts=family_sizes[
                        contrast.multiplicity_family_id
                    ],
                    multiplicity_method=config.multiplicity_method,
                )
                ci_low = linear_percentile(
                    bootstrap.estimates,
                    low_q,
                    method=config.percentile_method,
                )
                ci_high = linear_percentile(
                    bootstrap.estimates,
                    high_q,
                    method=config.percentile_method,
                )
                bootstrap_manifest_sha256 = canonical_sha256(
                    {
                        "schema_version": "1.0",
                        "state": "completed",
                        "effect_group": list(effect_group),
                        "analysis_config": config_payload,
                        "family_size": family_sizes[contrast.multiplicity_family_id],
                        "percentile_quantiles": [low_q, high_q],
                        "cluster_manifest_sha256": bootstrap.manifest_sha256,
                        "functional_provenance": functional_provenance,
                        "assignment_universe_sha256": assignment_universe_sha256,
                        "target_instance_universe_sha256": (target_instance_universe_sha256),
                    }
                )
            effect = ITTEffectRecord.from_content(
                hypothesis_id=hypothesis_id,
                target_spec_id=target_spec_id,
                arm_protocol_id=protocol_id,
                model_id=model_id,
                contrast_id=contrast.contrast_id,
                outcome_id=contrast.outcome_id,
                treatment_n=treatment_n,
                control_n=control_n,
                independent_task_n=len(task_ids),
                risk_difference=point,
                ci_low=ci_low,
                ci_high=ci_high,
                sensitivity_low=sensitivity_low,
                sensitivity_high=sensitivity_high,
                status=_status(
                    protocol,
                    contrast,
                    ci_low=ci_low,
                    ci_high=ci_high,
                    functional_supported=support_by_protocol[protocol_id],
                ),
                assignment_universe_sha256=assignment_universe_sha256,
                target_instance_universe_sha256=target_instance_universe_sha256,
                bootstrap_manifest_sha256=bootstrap_manifest_sha256,
            )
            effects.append(effect)
            if effect.status != "unsupported_missing_functional_outcome":
                draws.extend(
                    EffectBootstrapDrawRecord.from_content(
                        effect_id=effect.effect_id,
                        replicate_index=replicate_index,
                        sampled_task_ids=sampled_task_ids,
                        estimate=estimate,
                        assignment_universe_sha256=assignment_universe_sha256,
                        bootstrap_manifest_sha256=bootstrap_manifest_sha256,
                    )
                    for replicate_index, (sampled_task_ids, estimate) in enumerate(
                        zip(bootstrap.task_draws, bootstrap.estimates, strict=True)
                    )
                )
    ordered_effects = tuple(
        sorted(
            effects,
            key=lambda item: (
                item.hypothesis_id,
                item.target_spec_id,
                item.arm_protocol_id,
                item.model_id,
                item.contrast_id,
                item.outcome_id,
            ),
        )
    )
    ordered_draws = tuple(sorted(draws, key=lambda item: (item.effect_id, item.replicate_index)))
    ordered_failures = tuple(sorted(failures, key=lambda item: item.subject_id))
    return ITTEstimationResult(ordered_effects, ordered_draws, ordered_failures)


def estimate_itt(
    outcomes: Iterable[AssignmentOutcomeRecord],
    analysis_config: AnalysisConfig,
    *,
    protocols: Iterable[ConfirmationProtocolRecord],
    contrasts: Iterable[ContrastSpecRecord] | None = None,
    functional_contracts: Iterable[FunctionalOutcomeContractRecord] = (),
    functional_outcomes: Iterable[FunctionalOutcomeRecord] = (),
) -> tuple[ITTEffectRecord, ...]:
    """Compatibility wrapper returning only successfully estimated ITT effects."""

    result = calculate_itt(
        outcomes,
        analysis_config,
        protocols=protocols,
        contrasts=contrasts,
        functional_contracts=functional_contracts,
        functional_outcomes=functional_outcomes,
    )
    reasons = {failure.reason_code for failure in result.failures}
    if AnalysisFailureReason.INSUFFICIENT_SUPPORT in reasons:
        raise _itt_error("ITT requires minimum independent task count")
    if AnalysisFailureReason.BOOTSTRAP_FAILURE in reasons:
        raise _itt_error("ITT bootstrap manifest failed validation")
    return result.effects


def validate_itt_effects(
    outcomes: Iterable[AssignmentOutcomeRecord],
    analysis_config: AnalysisConfig,
    *,
    protocols: Iterable[ConfirmationProtocolRecord],
    effects: Iterable[ITTEffectRecord],
    contrasts: Iterable[ContrastSpecRecord] | None = None,
    functional_contracts: Iterable[FunctionalOutcomeContractRecord] = (),
    functional_outcomes: Iterable[FunctionalOutcomeRecord] = (),
) -> tuple[ITTEffectRecord, ...]:
    """Require exact count, order, and content against a fresh ITT recomputation."""

    try:
        expected = estimate_itt(
            outcomes,
            analysis_config,
            protocols=protocols,
            contrasts=contrasts,
            functional_contracts=functional_contracts,
            functional_outcomes=functional_outcomes,
        )
        checked, _by_id = _trusted_records(
            effects,
            ITTEffectRecord,
            "effect_id",
            allow_empty=False,
        )
        if checked != expected:
            raise _itt_error("ITT effect relation failed validation")
        return checked
    except _FATAL:
        raise
    except Exception:
        raise _itt_error("ITT effect relation failed validation") from None


__all__ = [
    "ITTEstimationResult",
    "MAX_ESTIMATOR_ARTIFACT_RECORDS",
    "MAX_ESTIMATOR_DRAW_RECORDS",
    "MAX_ESTIMATOR_SAMPLED_ROW_ENTRIES",
    "calculate_itt",
    "estimate_itt",
    "risk_difference",
    "validate_itt_effects",
]
