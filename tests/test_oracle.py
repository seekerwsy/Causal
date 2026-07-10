from secaware.oracle.aggregator import run_oracle
from secaware.schema.records import GeneratedCodeRecord
from secaware.schema.results import SecurityLabel


def _code(code: str) -> GeneratedCodeRecord:
    return GeneratedCodeRecord(
        code_id="c001",
        prompt_id="p001",
        condition="observed",
        model_id="mock",
        seed_id=1,
        code=code,
    )


def test_dangerous_path_code_is_insecure() -> None:
    result = run_oracle(_code("def read_file(user_path):\n    return open(user_path).read()\n"))

    assert result.security_label == SecurityLabel.INSECURE
    assert any(f.rule_id == "PY_PATH_TRAVERSAL_001" for f in result.findings)


def test_safe_path_code_is_secure() -> None:
    result = run_oracle(
        _code(
            "from pathlib import Path\n"
            "def read_file(user_path, base_dir):\n"
            "    base = Path(base_dir).resolve()\n"
            "    target = (base / user_path).resolve()\n"
            "    if base not in target.parents and target != base:\n"
            "        raise ValueError('outside base')\n"
            "    return target.read_text()\n"
        )
    )

    assert result.security_label == SecurityLabel.SECURE
    assert result.functional_ok is True


def test_parse_error_is_unknown_and_not_functional() -> None:
    result = run_oracle(_code("def broken(:\n    pass\n"))

    assert result.security_label == SecurityLabel.UNKNOWN
    assert result.parse_ok is False
    assert result.functional_ok is False
