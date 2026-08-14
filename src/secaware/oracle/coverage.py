"""Bind frozen prompt task profiles to authenticated Oracle negative coverage."""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence

from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.policy import LoadedOraclePolicy, OracleCoverageProfile
from secaware.schema.oracle import OracleEvaluability, OracleRecord, SecurityLabel
from secaware.schema.records import PromptRecord


_STAGE = "oracle_coverage"
_MESSAGE = "Oracle coverage binding failed validation"


def _error(message: str = _MESSAGE) -> SecAwareError:
    return SecAwareError(
        code=ErrorCode.CONTRACT,
        stage=_STAGE,
        message=message,
        details={},
        retryable=False,
    )


def _profile_index(policy: LoadedOraclePolicy) -> dict[str, OracleCoverageProfile]:
    profiles = {item.profile_id: item for item in policy.coverage_profiles}
    if len(profiles) != len(policy.coverage_profiles):
        raise _error()
    return profiles


def validate_prompt_coverage_profiles(
    prompts: Iterable[PromptRecord],
    policy: LoadedOraclePolicy,
) -> dict[str, OracleCoverageProfile]:
    """Authenticate the pre-treatment profile bound to every prompt."""

    try:
        if isinstance(prompts, (str, bytes, Mapping)):
            raise ValueError
        profile_by_id = _profile_index(policy)
        by_prompt: dict[str, OracleCoverageProfile] = {}
        for prompt in prompts:
            trusted = PromptRecord.model_validate(prompt.model_dump(mode="python"))
            profile = profile_by_id.get(trusted.oracle_profile_id or "")
            if (
                profile is None
                or profile.cwe != trusted.cwe
                or trusted.task_family not in profile.task_families
                or trusted.prompt_id in by_prompt
            ):
                raise ValueError
            by_prompt[trusted.prompt_id] = profile
        if not by_prompt:
            raise ValueError
        return by_prompt
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error() from None
    finally:
        prompts = ()
        policy = None  # type: ignore[assignment]


def apply_negative_coverage(
    records: Sequence[OracleRecord],
    prompts: Iterable[PromptRecord],
    policy: LoadedOraclePolicy,
) -> tuple[OracleRecord, ...]:
    """Upgrade authenticated zero-finding results only when coverage supports it."""

    try:
        profile_by_prompt = validate_prompt_coverage_profiles(prompts, policy)
        trusted_records = tuple(
            OracleRecord.model_validate(
                item.model_dump(mode="python", round_trip=True, warnings=False)
            )
            for item in records
        )
        if (
            not trusted_records
            or any(item.prompt_id not in profile_by_prompt for item in trusted_records)
        ):
            raise ValueError
        rebound: list[OracleRecord] = []
        for record in trusted_records:
            profile = profile_by_prompt[record.prompt_id]
            if (
                record.evaluability is OracleEvaluability.UNKNOWN_COVERAGE
                and record.security_label is SecurityLabel.UNKNOWN
                and profile.zero_finding_supported
            ):
                payload = record.model_dump(mode="python", round_trip=True, warnings=False)
                payload["security_label"] = SecurityLabel.SECURE
                payload["evaluability"] = OracleEvaluability.EVALUABLE
                record = OracleRecord.model_validate(payload)
            rebound.append(record)
        return tuple(rebound)
    except (MemoryError, KeyboardInterrupt, SystemExit):
        raise
    except SecAwareError:
        raise
    except Exception:
        raise _error() from None
    finally:
        records = ()
        prompts = ()
        policy = None  # type: ignore[assignment]


__all__ = ["apply_negative_coverage", "validate_prompt_coverage_profiles"]
