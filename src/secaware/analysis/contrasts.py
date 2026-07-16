"""Flatten only contrast definitions authenticated by committed M5 protocols."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from secaware.schema.common import model_shape_is_intact
from secaware.schema.experiments import ConfirmationProtocolRecord
from secaware.schema.outcomes import ContrastSpecRecord


_FATAL = (MemoryError, KeyboardInterrupt, SystemExit)


def _error() -> ValueError:
    return ValueError("contrast materialization failed validation")


def _trusted_protocols(
    protocols: Iterable[ConfirmationProtocolRecord],
) -> tuple[ConfirmationProtocolRecord, ...]:
    if isinstance(protocols, (str, bytes, Mapping)):
        raise _error()
    result: list[ConfirmationProtocolRecord] = []
    try:
        for index, protocol in enumerate(protocols):
            if (
                index >= 100_000
                or type(protocol) is not ConfirmationProtocolRecord
                or not model_shape_is_intact(protocol)
            ):
                raise _error()
            result.append(
                ConfirmationProtocolRecord.model_validate(
                    protocol.model_dump(mode="python", round_trip=True, warnings=False)
                )
            )
    except _FATAL:
        raise
    except Exception:
        raise _error() from None
    return tuple(result)


def materialize_contrasts(
    protocols: Iterable[ConfirmationProtocolRecord],
) -> tuple[ContrastSpecRecord, ...]:
    """Copy each nested frozen contrast field-for-field, preserving committed order."""

    records: list[ContrastSpecRecord] = []
    keys: set[tuple[str, str]] = set()
    try:
        for protocol in _trusted_protocols(protocols):
            for nested in protocol.contrasts:
                key = (protocol.arm_protocol_id, nested.contrast_id)
                if key in keys:
                    raise _error()
                record = ContrastSpecRecord(
                    schema_version="1.0",
                    contrast_id=nested.contrast_id,
                    arm_contrast_id=nested.arm_contrast_id,
                    arm_protocol_id=protocol.arm_protocol_id,
                    treatment_arm=nested.treatment_arm,
                    control_arm=nested.control_arm,
                    source_outcome_variable_id=nested.source_outcome_variable_id,
                    outcome_id=nested.outcome_id,
                    priority=nested.priority,
                    expected_sign=nested.expected_sign,
                    multiplicity_family_id=nested.multiplicity_family_id,
                )
                if any(
                    getattr(record, field) != getattr(nested, field)
                    for field in (
                        "contrast_id",
                        "arm_contrast_id",
                        "treatment_arm",
                        "control_arm",
                        "source_outcome_variable_id",
                        "outcome_id",
                        "priority",
                        "expected_sign",
                        "multiplicity_family_id",
                    )
                ):
                    raise _error()
                keys.add(key)
                records.append(record)
    except _FATAL:
        raise
    except Exception:
        raise _error() from None
    return tuple(records)


def validate_contrasts(
    protocols: Iterable[ConfirmationProtocolRecord],
    contrasts: Iterable[ContrastSpecRecord],
) -> tuple[ContrastSpecRecord, ...]:
    """Require a supplied flat relation to equal the protocol commitment exactly."""

    supplied: list[ContrastSpecRecord] = []
    try:
        expected = materialize_contrasts(protocols)
        if isinstance(contrasts, (str, bytes, Mapping)):
            raise _error()
        for index, contrast in enumerate(contrasts):
            if (
                index >= 100_000
                or type(contrast) is not ContrastSpecRecord
                or not model_shape_is_intact(contrast)
            ):
                raise _error()
            supplied.append(
                ContrastSpecRecord.model_validate(
                    contrast.model_dump(mode="python", round_trip=True, warnings=False)
                )
            )
        if tuple(supplied) != expected:
            raise _error()
        return expected
    except _FATAL:
        raise
    except Exception:
        raise _error() from None


__all__ = ["materialize_contrasts", "validate_contrasts"]
