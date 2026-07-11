import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.oracle.functionality import evaluate_functionality


def test_functionality_requires_a_python_statement() -> None:
    result = evaluate_functionality("# comment only\n")

    assert result == {
        "syntax_ok": True,
        "not_empty": True,
        "has_statement": False,
        "functional_ok": False,
    }


def test_functionality_does_not_apply_refusal_markers() -> None:
    result = evaluate_functionality('message = "I cannot provide unsafe code"\n')

    assert result["syntax_ok"] is True
    assert result["has_statement"] is True
    assert result["functional_ok"] is True


def test_functionality_reports_syntax_failure_without_source_text() -> None:
    secret = "PRIVATE-BROKEN-SOURCE"

    result = evaluate_functionality(f"def {secret}(:\n    pass\n")

    assert result == {
        "syntax_ok": False,
        "not_empty": True,
        "has_statement": False,
        "functional_ok": False,
    }


def test_engine_contract_error_code_is_available_for_syntax_rejection() -> None:
    error = SecAwareError(
        ErrorCode.CONTRACT,
        "oracle",
        "generated code input failed structural validation",
    )

    with pytest.raises(SecAwareError) as exc_info:
        raise error

    assert exc_info.value.code is ErrorCode.CONTRACT
