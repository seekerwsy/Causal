import json
import traceback
from collections.abc import Callable
from typing import Any

import pytest
from pydantic import ValidationError

from secaware.config import OpenAICompatibleConfig, OracleConfig
from secaware.schema.generation import (
    GenerationAttemptRecord,
    GenerationProvenance,
)
from secaware.schema.oracle import (
    AnalyzerFindingRecord,
    AnalyzerProvenanceRecord,
    OracleRecord,
    SecurityLabel,
)


_REQUEST_DIGEST = "a" * 64
_CODE_DIGEST = "b" * 64
_SEMGREP_POLICY_DIGEST = "c" * 64
_BANDIT_POLICY_DIGEST = "d" * 64


def _finding_payload(analyzer: str = "semgrep") -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "analyzer": analyzer,
        "rule_id": "python.lang.security.audit.command-injection",
        "cwe": "CWE-78",
        "severity": "high",
        "confidence": "high" if analyzer == "bandit" else "not_provided",
        "line": 7,
        "column": 9,
        "end_line": 7,
        "end_column": 24,
        "message": "Untrusted input reaches a command execution sink.",
    }


def _provenance_payload(analyzer: str) -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "analyzer": analyzer,
        "version": "1.168.0" if analyzer == "semgrep" else "1.9.4",
        "policy_sha256": (
            _SEMGREP_POLICY_DIGEST if analyzer == "semgrep" else _BANDIT_POLICY_DIGEST
        ),
    }


def _canonical_oracle_payload(
    *,
    condition: str = "observed",
    security_label: str = "insecure",
) -> dict[str, object]:
    counterfactual = condition == "counterfactual"
    return {
        "schema_version": "1.0",
        "request_id": f"req_{_REQUEST_DIGEST}",
        "code_id": f"code_{_REQUEST_DIGEST}",
        "code_sha256": _CODE_DIGEST,
        "prompt_id": "prompt-path-read",
        "condition": condition,
        "model_id": "model-a",
        "seed_id": 7,
        "hypothesis_id": "hypothesis-path-guard" if counterfactual else None,
        "intervention_id": "intervention-path-guard" if counterfactual else None,
        "parse_ok": True,
        "functional_ok": True,
        "security_label": security_label,
        "severity": "high" if security_label == "insecure" else "none",
        "findings": [_finding_payload()] if security_label == "insecure" else [],
        "analyzers": [
            _provenance_payload("semgrep"),
            _provenance_payload("bandit"),
        ],
    }


def _validation_surfaces(error: ValidationError) -> tuple[str, ...]:
    return (
        str(error),
        "".join(traceback.format_exception(error)),
        json.dumps(error.errors(), default=str, sort_keys=True),
        error.json(),
    )


def _secaware_traceback_frames(
    error: BaseException,
) -> list[tuple[str, dict[str, object]]]:
    retained: list[tuple[str, dict[str, object]]] = []
    current = error.__traceback__
    while current is not None:
        filename = current.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/secaware/" in filename:
            retained.append(
                (current.tb_frame.f_code.co_name, dict(current.tb_frame.f_locals))
            )
        current = current.tb_next
    return retained


def _secaware_traceback_locals(error: BaseException) -> str:
    return "\n".join(
        repr(frame_locals)
        for _, frame_locals in _secaware_traceback_frames(error)
    )


def _assert_safe_validation_error(error: ValidationError, *hidden: str) -> None:
    assert error.__cause__ is None
    assert error.__context__ is None
    structured = error.errors()
    assert len(structured) == 1
    assert structured[0]["loc"] == ()
    assert structured[0].get("input") is None
    assert "ctx" not in structured[0]
    retained = _secaware_traceback_locals(error)
    for value in hidden:
        assert all(value not in surface for surface in _validation_surfaces(error))
        assert value not in retained


def test_oracle_record_requires_analyzer_provenance_and_request_binding() -> None:
    record = OracleRecord.model_validate(_canonical_oracle_payload())

    assert record.schema_version == "1.0"
    assert record.request_id == f"req_{_REQUEST_DIGEST}"
    assert record.code_id == f"code_{_REQUEST_DIGEST}"
    assert record.code_sha256 == _CODE_DIGEST
    assert record.security_label is SecurityLabel.INSECURE
    assert {item.analyzer for item in record.analyzers} == {"semgrep", "bandit"}
    assert isinstance(record.findings, tuple)
    assert isinstance(record.analyzers, tuple)


def test_secure_oracle_record_has_no_findings_and_no_aggregate_severity() -> None:
    record = OracleRecord.model_validate(
        _canonical_oracle_payload(security_label="secure")
    )

    assert record.security_label is SecurityLabel.SECURE
    assert record.severity == "none"
    assert record.findings == ()


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("schema_version", "2.0"),
        ("analyzer", "custom"),
        ("rule_id", ""),
        ("rule_id", "   "),
        ("rule_id", "r" * 257),
        ("cwe", ""),
        ("cwe", "C" * 33),
        ("severity", "critical"),
        ("confidence", "unknown"),
        ("line", 0),
        ("line", True),
        ("column", 0),
        ("end_line", 0),
        ("end_column", 0),
        ("message", ""),
        ("message", "   "),
        ("message", "m" * 4097),
    ],
)
def test_analyzer_finding_rejects_invalid_fields(
    field: str,
    invalid_value: object,
) -> None:
    payload = _finding_payload()
    payload[field] = invalid_value

    with pytest.raises(ValidationError):
        AnalyzerFindingRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("line", "column", "end_line", "end_column"),
    [
        (8, 1, 7, 40),
        (8, 20, 8, 19),
    ],
)
def test_analyzer_finding_rejects_reversed_source_ranges(
    line: int,
    column: int,
    end_line: int,
    end_column: int,
) -> None:
    payload = _finding_payload()
    payload.update(
        line=line,
        column=column,
        end_line=end_line,
        end_column=end_column,
    )

    with pytest.raises(ValidationError):
        AnalyzerFindingRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("schema_version", "2.0"),
        ("analyzer", "ruff"),
        ("version", ""),
        ("version", "   "),
        ("version", "v" * 129),
        ("policy_sha256", "A" * 64),
        ("policy_sha256", "0" * 63),
    ],
)
def test_analyzer_provenance_rejects_invalid_fields(
    field: str,
    invalid_value: object,
) -> None:
    payload = _provenance_payload("semgrep")
    payload[field] = invalid_value

    with pytest.raises(ValidationError):
        AnalyzerProvenanceRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("schema_version", "2.0"),
        ("request_id", f"request_{_REQUEST_DIGEST}"),
        ("code_id", f"code_{'f' * 64}"),
        ("code_sha256", "F" * 64),
        ("prompt_id", "   "),
        ("model_id", ""),
        ("seed_id", True),
        ("parse_ok", 1),
        ("functional_ok", "true"),
        ("security_label", "unknown"),
        ("severity", "unknown"),
    ],
)
def test_oracle_record_rejects_invalid_contract_fields(
    field: str,
    invalid_value: object,
) -> None:
    payload = _canonical_oracle_payload()
    payload[field] = invalid_value

    with pytest.raises(ValidationError):
        OracleRecord.model_validate(payload)


@pytest.mark.parametrize(
    "analyzers",
    [
        [_provenance_payload("semgrep")],
        [_provenance_payload("bandit")],
        [
            _provenance_payload("semgrep"),
            _provenance_payload("semgrep"),
        ],
        [
            _provenance_payload("semgrep"),
            _provenance_payload("bandit"),
            _provenance_payload("bandit"),
        ],
    ],
)
def test_oracle_record_requires_exactly_one_of_each_analyzer(
    analyzers: list[dict[str, object]],
) -> None:
    payload = _canonical_oracle_payload()
    payload["analyzers"] = analyzers

    with pytest.raises(ValidationError):
        OracleRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("condition", "hypothesis_id", "intervention_id"),
    [
        ("observed", "unexpected", None),
        ("observed", None, "unexpected"),
        ("counterfactual", None, "intervention"),
        ("counterfactual", "hypothesis", None),
        ("counterfactual", "   ", "intervention"),
        ("counterfactual", "hypothesis", "   "),
    ],
)
def test_oracle_record_enforces_condition_identifiers(
    condition: str,
    hypothesis_id: str | None,
    intervention_id: str | None,
) -> None:
    payload = _canonical_oracle_payload(condition=condition)
    payload["hypothesis_id"] = hypothesis_id
    payload["intervention_id"] = intervention_id

    with pytest.raises(ValidationError):
        OracleRecord.model_validate(payload)


@pytest.mark.parametrize(
    ("security_label", "severity", "findings"),
    [
        ("secure", "low", []),
        ("secure", "none", [_finding_payload()]),
        ("insecure", "none", [_finding_payload()]),
        ("insecure", "high", []),
        ("insecure", "medium", [_finding_payload()]),
    ],
)
def test_oracle_record_enforces_label_severity_and_findings_consistency(
    security_label: str,
    severity: str,
    findings: list[dict[str, object]],
) -> None:
    payload = _canonical_oracle_payload(security_label=security_label)
    payload["severity"] = severity
    payload["findings"] = findings

    with pytest.raises(ValidationError):
        OracleRecord.model_validate(payload)


def test_oracle_record_is_deeply_immutable() -> None:
    record = OracleRecord.model_validate(_canonical_oracle_payload())

    with pytest.raises(ValidationError):
        record.code_id = f"code_{'0' * 64}"
    with pytest.raises(ValidationError):
        record.findings[0].message = "changed"
    with pytest.raises(AttributeError):
        record.findings.append(AnalyzerFindingRecord.model_validate(_finding_payload()))


@pytest.mark.parametrize(
    "forgery",
    [
        "top_level_copy",
        "top_level_construct",
        "nested_finding_copy",
        "nested_finding_construct",
        "nested_provenance_copy",
        "nested_provenance_construct",
    ],
)
def test_oracle_revalidation_rejects_model_copy_and_construct_forgery(
    forgery: str,
) -> None:
    valid = OracleRecord.model_validate(_canonical_oracle_payload())
    if forgery == "top_level_copy":
        forged: object = valid.model_copy(update={"code_sha256": "forged"})
    elif forgery == "top_level_construct":
        payload = valid.model_dump(mode="python")
        payload.pop("request_id")
        forged = OracleRecord.model_construct(**payload)
    elif forgery == "nested_finding_copy":
        finding = valid.findings[0].model_copy(update={"line": 0})
        forged = valid.model_copy(update={"findings": (finding,)})
    elif forgery == "nested_finding_construct":
        finding_payload = valid.findings[0].model_dump(mode="python")
        finding_payload.pop("rule_id")
        finding = AnalyzerFindingRecord.model_construct(**finding_payload)
        forged = valid.model_copy(update={"findings": (finding,)})
    elif forgery == "nested_provenance_copy":
        provenance = valid.analyzers[0].model_copy(update={"version": " "})
        forged = valid.model_copy(
            update={"analyzers": (provenance, valid.analyzers[1])}
        )
    else:
        provenance_payload = valid.analyzers[0].model_dump(mode="python")
        provenance_payload.pop("policy_sha256")
        provenance = AnalyzerProvenanceRecord.model_construct(**provenance_payload)
        forged = valid.model_copy(
            update={"analyzers": (provenance, valid.analyzers[1])}
        )

    with pytest.raises(ValidationError):
        OracleRecord.model_validate(forged)


@pytest.mark.parametrize(
    "surface",
    ["constructor", "python", "json", "strings"],
)
def test_oracle_validation_four_public_surfaces_hide_input_and_frame_locals(
    surface: str,
) -> None:
    secret = f"oracle-{surface}-private-input"
    payload = _canonical_oracle_payload()
    payload["private_credential"] = secret
    operations: dict[str, Callable[[], object]] = {
        "constructor": lambda: OracleRecord(**payload),
        "python": lambda: OracleRecord.model_validate(payload),
        "json": lambda: OracleRecord.model_validate_json(json.dumps(payload)),
        "strings": lambda: OracleRecord.model_validate_strings(
            {"private_credential": secret}
        ),
    }

    with pytest.raises(ValidationError) as exc_info:
        operations[surface]()

    _assert_safe_validation_error(
        exc_info.value,
        secret,
        "private_credential",
        "input_value",
    )


def test_oracle_config_is_fail_closed_and_immutable() -> None:
    config = OracleConfig()

    assert config.language == "python"
    assert config.policy_lock_path == "policies/oracle/python/policy.lock.json"
    assert config.semgrep_executable == "semgrep"
    assert config.bandit_executable == "bandit"
    assert config.timeout_seconds == 120.0
    assert config.max_stdout_bytes == 64 * 1024 * 1024
    assert config.max_stderr_bytes == 4 * 1024 * 1024
    with pytest.raises(ValidationError):
        config.language = "javascript"  # type: ignore[assignment]


@pytest.mark.parametrize(
    ("field", "invalid_value"),
    [
        ("language", "javascript"),
        ("policy_lock_path", ""),
        ("policy_lock_path", "   "),
        ("policy_lock_path", "p" * 4097),
        ("semgrep_executable", ""),
        ("semgrep_executable", " semgrep"),
        ("semgrep_executable", "s" * 1025),
        ("bandit_executable", ""),
        ("bandit_executable", "bandit "),
        ("timeout_seconds", 0.0),
        ("timeout_seconds", 3600.1),
        ("timeout_seconds", "120"),
        ("max_stdout_bytes", 1023),
        ("max_stdout_bytes", 256 * 1024 * 1024 + 1),
        ("max_stdout_bytes", True),
        ("max_stderr_bytes", 1023),
        ("max_stderr_bytes", 64 * 1024 * 1024 + 1),
    ],
)
def test_oracle_config_rejects_invalid_values(
    field: str,
    invalid_value: object,
) -> None:
    with pytest.raises(ValidationError):
        OracleConfig.model_validate({field: invalid_value})


@pytest.mark.parametrize(
    "legacy_key",
    [
        "policy_name",
        "use_lightweight_rules",
        "use_bandit",
        "use_semgrep",
        "fail_on_parse_error",
    ],
)
def test_oracle_config_rejects_legacy_behavior_keys(legacy_key: str) -> None:
    with pytest.raises(ValidationError):
        OracleConfig.model_validate({legacy_key: True})


def test_oracle_config_revalidates_forged_instances() -> None:
    forged = OracleConfig().model_copy(update={"timeout_seconds": -1.0})

    with pytest.raises(ValidationError):
        OracleConfig.model_validate(forged)


def test_oracle_config_validation_hides_values_and_frame_locals() -> None:
    secret = "private-oracle-executable-path"
    field = "semgrep_executable"

    with pytest.raises(ValidationError) as exc_info:
        OracleConfig.model_validate({field: secret + "\x00"})

    _assert_safe_validation_error(exc_info.value, secret, field)


def test_results_module_reexports_canonical_oracle_contracts() -> None:
    from secaware.schema import (
        AnalyzerFindingRecord as PackageAnalyzerFindingRecord,
    )
    from secaware.schema import (
        AnalyzerProvenanceRecord as PackageAnalyzerProvenanceRecord,
    )
    from secaware.schema import OracleRecord as PackageOracleRecord
    from secaware.schema.results import FindingRecord
    from secaware.schema.results import OracleRecord as ResultsOracleRecord
    from secaware.schema.results import SecurityLabel as ResultsSecurityLabel

    assert FindingRecord is AnalyzerFindingRecord
    assert ResultsOracleRecord is OracleRecord is PackageOracleRecord
    assert ResultsSecurityLabel is SecurityLabel
    assert PackageAnalyzerFindingRecord is AnalyzerFindingRecord
    assert PackageAnalyzerProvenanceRecord is AnalyzerProvenanceRecord


def test_oracle_contracts_reject_unknown_fields() -> None:
    payload: dict[str, Any] = _canonical_oracle_payload()
    payload["unexpected"] = "value"

    with pytest.raises(ValidationError):
        OracleRecord.model_validate(payload)


def _validate_at_entrypoint(
    model: type[Any],
    payload: dict[str, object],
    entrypoint: str,
) -> object:
    if entrypoint == "constructor":
        return model(**payload)
    if entrypoint == "model_validate":
        return model.model_validate(payload)
    if entrypoint == "model_validate_json":
        return model.model_validate_json(json.dumps(payload))
    return model.model_validate_strings(payload, strict=False)


def _stringly_finding_payload() -> dict[str, object]:
    payload = _finding_payload()
    for field in ("line", "column", "end_line", "end_column"):
        payload[field] = str(payload[field])
    return payload


def _stringly_attempt_payload() -> dict[str, object]:
    return {
        "schema_version": "1.0",
        "request_id": f"req_{_REQUEST_DIGEST}",
        "attempt": "1",
        "outcome": "retry",
        "error_code": "22",
        "retryable": "true",
        "backoff_seconds": "1.0",
    }


@pytest.mark.parametrize(
    "entrypoint",
    ["constructor", "model_validate", "model_validate_json", "model_validate_strings"],
)
@pytest.mark.parametrize(
    ("model", "payload"),
    [
        pytest.param(
            AnalyzerFindingRecord,
            _stringly_finding_payload(),
            id="oracle-finding-int-strings",
        ),
        pytest.param(
            OracleRecord,
            {
                **_canonical_oracle_payload(),
                "seed_id": "7",
                "parse_ok": "true",
                "functional_ok": "true",
            },
            id="oracle-record-int-bool-strings",
        ),
        pytest.param(
            OracleConfig,
            {
                "timeout_seconds": "120.0",
                "max_stdout_bytes": "1024",
                "max_stderr_bytes": "1024",
            },
            id="oracle-config-float-int-strings",
        ),
        pytest.param(
            GenerationAttemptRecord,
            _stringly_attempt_payload(),
            id="existing-attempt-int-float-bool-strings",
        ),
        pytest.param(
            OpenAICompatibleConfig,
            {
                "base_url": "https://provider.invalid/v1",
                "timeout_seconds": "60.0",
            },
            id="existing-provider-config-float-string",
        ),
    ],
)
def test_safe_models_reject_stringly_typed_primitives_at_every_entrypoint(
    model: type[Any],
    payload: dict[str, object],
    entrypoint: str,
) -> None:
    with pytest.raises(ValidationError):
        _validate_at_entrypoint(model, payload, entrypoint)


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        pytest.param(
            AnalyzerFindingRecord,
            _finding_payload(),
            id="oracle-finding",
        ),
        pytest.param(
            OracleRecord,
            _canonical_oracle_payload(),
            id="oracle-record",
        ),
        pytest.param(
            OracleConfig,
            {
                "timeout_seconds": 120.0,
                "max_stdout_bytes": 1024,
                "max_stderr_bytes": 1024,
            },
            id="oracle-config",
        ),
        pytest.param(
            GenerationAttemptRecord,
            {
                "schema_version": "1.0",
                "request_id": f"req_{_REQUEST_DIGEST}",
                "attempt": 1,
                "outcome": "retry",
                "error_code": 22,
                "retryable": True,
                "backoff_seconds": 1.0,
            },
            id="existing-attempt",
        ),
    ],
)
def test_model_validate_strings_uses_strict_python_semantics_for_valid_payloads(
    model: type[Any],
    payload: dict[str, object],
) -> None:
    expected = model.model_validate(payload)

    actual = model.model_validate_strings(payload, strict=False)

    assert actual == expected


def test_model_validate_strings_keeps_valid_string_only_fields() -> None:
    provenance = AnalyzerProvenanceRecord.model_validate_strings(
        _provenance_payload("semgrep"),
        strict=False,
    )
    generation = GenerationProvenance.model_validate_strings(
        {
            "producer": "offline-import",
            "producer_version": "1.0",
            "source_batch_id": "batch-a",
        },
        strict=False,
    )

    assert provenance.version == "1.168.0"
    assert generation.producer == "offline-import"


def _frozen_assignment_case(
    case: str,
) -> tuple[object, str, str, tuple[str, ...]]:
    replacement = f"{case}-replacement-frame-sentinel"
    if case == "finding":
        payload = _finding_payload()
        payload.update(
            rule_id="finding-rule-frame-sentinel",
            cwe="CWE-finding-frame-sentinel",
            message="finding-message-frame-sentinel",
        )
        record: object = AnalyzerFindingRecord.model_validate(payload)
        return record, "message", replacement, (
            "finding-rule-frame-sentinel",
            "CWE-finding-frame-sentinel",
            "finding-message-frame-sentinel",
            replacement,
        )
    if case == "provenance":
        payload = _provenance_payload("semgrep")
        payload["version"] = "provenance-version-frame-sentinel"
        record = AnalyzerProvenanceRecord.model_validate(payload)
        return record, "version", replacement, (
            "provenance-version-frame-sentinel",
            replacement,
        )
    if case == "oracle":
        payload = _canonical_oracle_payload(security_label="secure")
        payload["prompt_id"] = "oracle-prompt-frame-sentinel"
        record = OracleRecord.model_validate(payload)
        return record, "prompt_id", replacement, (
            "oracle-prompt-frame-sentinel",
            replacement,
        )
    record = OracleConfig(
        semgrep_executable="config-executable-frame-sentinel"
    )
    return record, "semgrep_executable", replacement, (
        "config-executable-frame-sentinel",
        replacement,
    )


@pytest.mark.parametrize("case", ["finding", "provenance", "oracle", "config"])
def test_frozen_assignment_errors_clear_models_values_and_analyzer_output_from_frames(
    case: str,
) -> None:
    record, field, replacement, hidden = _frozen_assignment_case(case)
    original = getattr(record, field)

    with pytest.raises(ValidationError) as exc_info:
        setattr(record, field, replacement)

    error = exc_info.value
    assert error.__cause__ is None
    assert error.__context__ is None
    assert getattr(record, field) == original
    frames = _secaware_traceback_frames(error)
    assignment_frames = [locals_ for name, locals_ in frames if name == "__setattr__"]
    assert len(assignment_frames) == 1
    assignment_locals = assignment_frames[0]
    assert assignment_locals.get("self") is None
    assert assignment_locals.get("name") == ""
    assert assignment_locals.get("value") is None
    for _, frame_locals in frames:
        assert all(id(value) != id(record) for value in frame_locals.values())
        rendered = repr(frame_locals)
        assert all(value not in rendered for value in hidden)


def test_analyzer_finding_repr_hides_raw_analyzer_output() -> None:
    payload = _finding_payload()
    payload.update(
        analyzer="bandit",
        rule_id="repr-private-rule",
        cwe="CWE-repr-private",
        severity="medium",
        confidence="low",
        message="repr-private-message",
    )
    finding = AnalyzerFindingRecord.model_validate(payload)

    rendered = repr(finding)

    for hidden in (
        "bandit",
        "repr-private-rule",
        "CWE-repr-private",
        "medium",
        "low",
        "repr-private-message",
        "line=",
        "column=",
        "end_line=",
        "end_column=",
    ):
        assert hidden not in rendered
