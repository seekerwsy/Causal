from pathlib import Path

import pytest
from pydantic import ValidationError

import secaware.errors as errors
from secaware.config import AppConfig, FCIDiscoveryConfig, load_config
from secaware.errors import ErrorCode, SecAwareError


PROJECT_ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize(
    ("member", "value"),
    [
        (ErrorCode.CONFIG, 2),
        (ErrorCode.CONTRACT, 3),
        (ErrorCode.EXTERNAL_INPUT_REQUIRED, 4),
        (ErrorCode.API_AUTH, 20),
        (ErrorCode.API_RATE_LIMIT, 21),
        (ErrorCode.API_TIMEOUT, 22),
        (ErrorCode.API_INVALID_RESPONSE, 23),
        (ErrorCode.API_RETRIES_EXHAUSTED, 24),
        (ErrorCode.ANALYZER_MISSING, 30),
        (ErrorCode.ANALYZER_FAILED, 31),
        (ErrorCode.ANALYZER_INVALID_OUTPUT, 32),
        (ErrorCode.POLICY_MISMATCH, 33),
        (ErrorCode.MANIFEST_CONFLICT, 40),
        (ErrorCode.TSG_INVALID, 50),
        (ErrorCode.ANALYSIS_INVALID, 60),
    ],
)
def test_error_code_values_are_stable(member: ErrorCode, value: int) -> None:
    assert isinstance(member, int)
    assert member.value == value


def test_secaware_error_serializes_details_but_hides_them_from_str() -> None:
    details = {"provider_host": "internal.example", "request_id": "req-123"}
    error = SecAwareError(
        code=ErrorCode.API_TIMEOUT,
        stage="generation",
        message="provider request timed out",
        details=details,
        retryable=True,
    )

    assert error.to_dict() == {
        "code": 22,
        "stage": "generation",
        "message": "provider request timed out",
        "details": details,
        "retryable": True,
    }
    rendered = str(error)
    assert "API_TIMEOUT" in rendered
    assert "generation" in rendered
    assert "provider request timed out" in rendered
    assert "provider_host" not in rendered
    assert "internal.example" not in rendered
    assert "request_id" not in rendered
    assert "req-123" not in rendered


def test_secaware_error_redacts_sensitive_detail_keys_recursively() -> None:
    details = {
        "Api_KeyFingerprint": "key-material",
        "AUTHORIZATION_header": "Bearer credential",
        "refreshToken": "refresh-credential",
        "client_SECRET_value": "client-credential",
        "dbPASSWORD": "database-credential",
        "nested": [
            {
                "safe": "visible",
                "session_token_id": "session-credential",
                "deeper": {"passwordHash": "password-hash"},
            }
        ],
    }
    error = SecAwareError(
        code=ErrorCode.API_AUTH,
        stage="generation",
        message="provider authentication failed",
        details=details,
    )
    expected = {
        "Api_KeyFingerprint": "[REDACTED]",
        "AUTHORIZATION_header": "[REDACTED]",
        "refreshToken": "[REDACTED]",
        "client_SECRET_value": "[REDACTED]",
        "dbPASSWORD": "[REDACTED]",
        "nested": [
            {
                "safe": "visible",
                "session_token_id": "[REDACTED]",
                "deeper": {"passwordHash": "[REDACTED]"},
            }
        ],
    }

    assert error.details == expected
    assert error.to_dict()["details"] == expected


@pytest.mark.parametrize(
    "sensitive_key",
    [
        "api_key",
        "apikey",
        "API.Key",
        "authorization",
        "Authorization-Header",
        "token",
        "tokens",
        "api_token",
        "AUTH-TOKEN",
        "tokenValue",
        "apiTokenValue",
        "accessTokenValue",
        "auth",
        "bearer",
        "BearerToken",
        "secret",
        "Secret.Key",
        "password",
        "DB.Password",
        "private_key",
        "Private-Key",
        "credential",
        "credentials",
        "client_credentials",
        "Client-Credentials",
    ],
)
def test_sensitive_key_rule_and_error_detail_redaction_are_consistent(
    sensitive_key: str,
) -> None:
    secret = f"sensitive-value-for-{sensitive_key}"

    assert errors.is_sensitive_key(sensitive_key) is True
    error = SecAwareError(
        code=ErrorCode.API_AUTH,
        stage="generation",
        message="provider authentication failed",
        details={"nested": [{sensitive_key: secret}]},
    )

    assert error.details == {"nested": [{sensitive_key: "[REDACTED]"}]}
    assert secret not in str(error.to_dict())


@pytest.mark.parametrize(
    "usage_key",
    [
        "max_tokens",
        "MaxTokens",
        "min_tokens",
        "input_tokens",
        "InputTokens",
        "output_tokens",
        "completion_tokens",
        "prompt_tokens",
        "total_tokens",
        "token_count",
        "max_completion_tokens",
        "MaxCompletionTokens",
        "max_output_tokens",
    ],
)
def test_sensitive_key_rule_allows_noncredential_token_usage_keys(usage_key: str) -> None:
    assert errors.is_sensitive_key(usage_key) is False
    error = SecAwareError(
        code=ErrorCode.API_TIMEOUT,
        stage="generation",
        message="provider request timed out",
        details={usage_key: 42},
    )

    assert error.details == {usage_key: 42}


def test_secaware_error_details_are_independent_snapshots() -> None:
    details = {
        "attempts": [{"status": "pending"}],
        "coordinates": (1, 2),
    }
    error = SecAwareError(
        code=ErrorCode.API_TIMEOUT,
        stage="generation",
        message="provider request timed out",
        details=details,
    )

    details["attempts"][0]["status"] = "mutated"
    details["attempts"].append({"status": "added"})
    serialized = error.to_dict()
    serialized["details"]["attempts"][0]["status"] = "serialized mutation"

    assert error.details == {
        "attempts": [{"status": "pending"}],
        "coordinates": [1, 2],
    }
    assert error.to_dict()["details"] == error.details


@pytest.mark.parametrize(
    "details",
    [
        {"unsupported": object()},
        {"nested": [object()]},
        {1: "non-string key"},
    ],
)
def test_secaware_error_rejects_non_json_details(details: dict[object, object]) -> None:
    with pytest.raises(TypeError):
        SecAwareError(
            code=ErrorCode.CONTRACT,
            stage="validation",
            message="invalid details",
            details=details,
        )


def test_app_config_rejects_unknown_nested_keys() -> None:
    with pytest.raises(ValidationError) as exc_info:
        AppConfig.model_validate(
            {
                "run": {"name": "strict", "unexpected": True},
                "data": {"prompts_path": "prompts.jsonl"},
            }
        )

    assert ("run", "unexpected") in {tuple(error["loc"]) for error in exc_info.value.errors()}


@pytest.mark.parametrize("random_seed", (True, 1.0, -(2**63) - 1, 2**63))
def test_run_random_seed_is_a_strict_signed_64_bit_integer(random_seed: object) -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate(
            {
                "run": {"name": "strict", "random_seed": random_seed},
                "data": {"prompts_path": "prompts.jsonl"},
                "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
            }
        )


@pytest.mark.parametrize("random_seed", (-(2**63), 0, 2**63 - 1))
def test_run_random_seed_accepts_signed_64_bit_boundaries(random_seed: int) -> None:
    config = AppConfig.model_validate(
        {
            "run": {"name": "strict", "random_seed": random_seed},
            "data": {"prompts_path": "prompts.jsonl"},
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
        }
    )

    assert config.run.random_seed == random_seed


def test_app_config_rejects_removed_tsg_field() -> None:
    removed_field = "code_" + "extractor"
    removed_value = "python_" + "ast_v0"

    with pytest.raises(ValidationError) as exc_info:
        AppConfig.model_validate(
            {
                "run": {"name": "strict"},
                "data": {"prompts_path": "prompts.jsonl"},
                "tsg": {removed_field: removed_value},
            }
        )

    assert ("tsg", removed_field) in {tuple(error["loc"]) for error in exc_info.value.errors()}


def test_app_config_uses_exact_bounded_fci_discovery_contract() -> None:
    config = AppConfig.model_validate(
        {
            "run": {"name": "strict"},
            "data": {"prompts_path": "prompts.jsonl"},
            "tsg": {"prompt_extractor": "deterministic_catalog_v1"},
        }
    )

    assert type(config.discovery) is FCIDiscoveryConfig
    assert config.discovery.model_dump(mode="json") == {
        "backend": "causal_learn_fci_v1",
        "backend_version": "0.1.4.7",
        "ci_test": "gsq",
        "alpha": 0.05,
        "depth": 3,
        "max_path_length": 6,
        "timeout_seconds": 120.0,
        "max_variables": 64,
        "max_rows": 100_000,
        "bootstrap_samples": 200,
        "stability_threshold": 0.80,
        "max_candidate_paths": 512,
        "min_independent_tasks": 20,
        "max_failed_bootstrap_fraction": 0.10,
    }


@pytest.mark.parametrize(
    "removed_field",
    ("min_support_total", "min_support_each_side", "top_k_per_scope", "score_weights"),
)
def test_app_config_rejects_removed_heuristic_discovery_fields(removed_field: str) -> None:
    with pytest.raises(ValidationError):
        AppConfig.model_validate(
            {
                "run": {"name": "strict"},
                "data": {"prompts_path": "prompts.jsonl"},
                "discovery": {removed_field: 1},
            }
        )


@pytest.mark.parametrize("config_name", ["demo.yaml", "paper_v0.yaml"])
def test_existing_config_files_still_load(config_name: str) -> None:
    config = load_config(PROJECT_ROOT / "configs" / config_name)

    assert config.run.name == Path(config_name).stem
    assert config.data.prompts_path == "data/examples/prompts_demo.jsonl"
