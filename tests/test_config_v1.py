from pathlib import Path

import pytest
from pydantic import ValidationError

from secaware.config import AppConfig, load_config
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
    details = {"api_key": "top-secret", "request_id": "req-123"}
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
    assert "api_key" not in rendered
    assert "top-secret" not in rendered
    assert "request_id" not in rendered
    assert "req-123" not in rendered


def test_app_config_rejects_unknown_nested_keys() -> None:
    with pytest.raises(ValidationError) as exc_info:
        AppConfig.model_validate(
            {
                "run": {"name": "strict", "unexpected": True},
                "data": {"prompts_path": "prompts.jsonl"},
            }
        )

    assert ("run", "unexpected") in {
        tuple(error["loc"]) for error in exc_info.value.errors()
    }


@pytest.mark.parametrize("config_name", ["demo.yaml", "paper_v0.yaml"])
def test_existing_config_files_still_load(config_name: str) -> None:
    config = load_config(PROJECT_ROOT / "configs" / config_name)

    assert config.run.name == Path(config_name).stem
    assert config.data.prompts_path == "data/examples/prompts_demo.jsonl"

