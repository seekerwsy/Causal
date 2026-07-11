from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import stat
import sys
import traceback

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.oracle.aggregator import run_oracle_batch
from secaware.oracle.policy import LoadedOraclePolicy, load_policy_bundle
from secaware.oracle.runner import AnalyzerProcessResult
from secaware.schema.generation import (
    GENERATION_REQUEST_SCHEMA_VERSION,
    GenerationParameters,
    GenerationProvenance,
    GenerationRequestRecord,
    build_generation_request_id,
    sha256_text,
)
from secaware.schema.oracle import SecurityLabel
from secaware.schema.records import CanonicalGeneratedCodeRecord, GeneratedCodeRecord


_POLICY_LOCK = (
    Path(__file__).parents[1] / "policies" / "oracle" / "python" / "policy.lock.json"
)


def _request(*, prompt_id: str, seed_id: int) -> GenerationRequestRecord:
    prompt = f"Return Python for {prompt_id}."
    parameters = GenerationParameters(values={"temperature": 0.0})
    prompt_sha256 = sha256_text(prompt)
    endpoint_sha256 = sha256_text("offline")
    template = "Return only code."
    template_sha256 = sha256_text(template)
    request_id = build_generation_request_id(
        schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
        condition="observed",
        prompt_id=prompt_id,
        prompt_sha256=prompt_sha256,
        language="python",
        model_id="model-a",
        seed_id=seed_id,
        hypothesis_id=None,
        intervention_id=None,
        endpoint_type="offline",
        endpoint_sha256=endpoint_sha256,
        system_template_version="template-v1",
        system_template_sha256=template_sha256,
        parameters=parameters,
    )
    return GenerationRequestRecord(
        schema_version=GENERATION_REQUEST_SCHEMA_VERSION,
        request_id=request_id,
        condition="observed",
        prompt_id=prompt_id,
        prompt=prompt,
        prompt_sha256=prompt_sha256,
        language="python",
        model_id="model-a",
        seed_id=seed_id,
        hypothesis_id=None,
        intervention_id=None,
        endpoint_type="offline",
        endpoint_sha256=endpoint_sha256,
        system_template_version="template-v1",
        system_template_sha256=template_sha256,
        parameters=parameters,
    )


def _code(
    *,
    prompt_id: str = "prompt-a",
    seed_id: int = 1,
    code: str = "def answer():\n    return 42\n",
) -> CanonicalGeneratedCodeRecord:
    return canonical_generated_code_from_request(
        _request(prompt_id=prompt_id, seed_id=seed_id),
        code,
        GenerationProvenance(
            producer="offline-worker",
            producer_version="1",
            source_batch_id="batch-1",
        ),
    )


def _source_names(cwd: Path) -> tuple[str, ...]:
    return tuple(sorted(path.name for path in cwd.iterdir() if path.suffix == ".py"))


def _semgrep_result(filename: str) -> dict[str, object]:
    return {
        "check_id": "secaware.python.command-injection",
        "path": filename,
        "start": {"line": 1, "col": 1, "offset": 0},
        "end": {"line": 1, "col": 4, "offset": 3},
        "extra": {
            "message": "private analyzer rendering",
            "metadata": {"cwe": "CWE-78"},
            "severity": "ERROR",
            "is_ignored": False,
        },
    }


def _bandit_result(filename: str) -> dict[str, object]:
    return {
        "code": "private analyzer source",
        "col_offset": 0,
        "end_col_offset": 3,
        "filename": filename,
        "issue_confidence": "HIGH",
        "issue_cwe": {"id": 78},
        "issue_severity": "LOW",
        "issue_text": "private analyzer rendering",
        "line_number": 1,
        "line_range": [1],
        "test_id": "B603",
        "test_name": "subprocess_without_shell_equals_true",
    }


class FakeRunner:
    def __init__(
        self,
        *,
        finding: str | None = None,
        failure: str | None = None,
        control: KeyboardInterrupt | SystemExit | None = None,
        inspect_batch: Callable[[Sequence[str], Path], None] | None = None,
    ) -> None:
        self.finding = finding
        self.failure = failure
        self.control = control
        self.inspect_batch = inspect_batch
        self.calls: list[tuple[tuple[str, ...], Path, float, int, int]] = []
        self.batch_dirs: list[Path] = []

    def __call__(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        timeout_seconds: float,
        max_stdout_bytes: int,
        max_stderr_bytes: int,
    ) -> AnalyzerProcessResult:
        argv = tuple(argv)
        self.calls.append(
            (argv, cwd, timeout_seconds, max_stdout_bytes, max_stderr_bytes)
        )
        self.batch_dirs.append(cwd)
        if self.inspect_batch is not None:
            self.inspect_batch(argv, cwd)
        analyzer = "semgrep" if "scan" in argv else "bandit"
        if analyzer == "semgrep" and self.control is not None:
            raise self.control
        if self.failure == analyzer:
            raise SecAwareError(
                ErrorCode.ANALYZER_FAILED,
                "oracle_analyzer",
                "analyzer process did not complete successfully",
            )
        files = _source_names(cwd)
        covered = files[:-1] if self.failure == f"{analyzer}_partial" else files
        if analyzer == "semgrep":
            results = [_semgrep_result(files[0])] if self.finding == analyzer else []
            payload = {
                "version": "1.168.0",
                "results": results,
                "errors": [],
                "paths": {"scanned": list(covered)},
                "skipped_rules": [],
            }
            if self.failure == "semgrep_malformed":
                stdout = b"PRIVATE-INVALID-REPORT"
            else:
                stdout = json.dumps(payload).encode("utf-8")
            return AnalyzerProcessResult(
                returncode=0,
                stdout=stdout,
                argv_sha256="a" * 64,
            )
        results = [_bandit_result(files[0])] if self.finding == analyzer else []
        metrics = {
            filename: {"loc": 3, "nosec": 0, "skipped_tests": 0}
            for filename in covered
        }
        metrics["_totals"] = {"loc": 3, "nosec": 0, "skipped_tests": 0}
        payload = {"errors": [], "metrics": metrics, "results": results}
        return AnalyzerProcessResult(
            returncode=1 if results else 0,
            stdout=json.dumps(payload).encode("utf-8"),
            argv_sha256="b" * 64,
        )


@pytest.fixture
def policy() -> LoadedOraclePolicy:
    return load_policy_bundle(_POLICY_LOCK)


@pytest.fixture(autouse=True)
def supported_runtime(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def validate() -> object:
        calls.append("validated")
        return object()

    monkeypatch.setattr("secaware.oracle.aggregator.validate_analyzer_runtime", validate)
    return calls


def test_both_clean_reports_produce_secure_records_and_run_each_tool_once(
    policy: LoadedOraclePolicy,
    supported_runtime: list[str],
) -> None:
    codes = [
        _code(prompt_id="prompt-b", seed_id=2),
        _code(prompt_id="prompt-a", seed_id=1),
    ]
    runner = FakeRunner()

    records = run_oracle_batch(
        codes,
        policy,
        semgrep_executable="semgrep-test",
        bandit_executable="bandit-test",
        timeout_seconds=7.5,
        max_stdout_bytes=8192,
        max_stderr_bytes=2048,
        runner=runner,
    )

    assert supported_runtime == ["validated"]
    assert len(runner.calls) == 2
    assert ["scan" in call[0] for call in runner.calls] == [True, False]
    assert all(call[1] == runner.calls[0][1] for call in runner.calls)
    assert all(call[2:] == (7.5, 8192, 2048) for call in runner.calls)
    assert runner.calls[0][0][-1] == "."
    assert runner.calls[1][0][2] == "."
    assert [record.request_id for record in records] == sorted(
        code.request_id for code in codes
    )
    assert all(record.security_label is SecurityLabel.SECURE for record in records)
    assert all(record.severity == "none" for record in records)
    assert all(record.findings == () for record in records)
    assert all(
        tuple(item.analyzer for item in record.analyzers) == ("semgrep", "bandit")
        for record in records
    )
    assert all(
        {item.policy_sha256 for item in record.analyzers}
        == {policy.combined_sha256}
        for record in records
    )
    assert all(not path.exists() for path in runner.batch_dirs)


@pytest.mark.parametrize("analyzer", ["semgrep", "bandit"])
def test_either_analyzer_finding_produces_insecure(
    analyzer: str,
    policy: LoadedOraclePolicy,
) -> None:
    runner = FakeRunner(finding=analyzer)

    record = run_oracle_batch([_code()], policy, runner=runner)[0]

    assert record.security_label is SecurityLabel.INSECURE
    assert record.severity == ("high" if analyzer == "semgrep" else "low")
    assert len(record.findings) == 1
    assert record.findings[0].analyzer == analyzer


def test_batch_materializes_authenticated_policy_and_opaque_deterministic_sources(
    policy: LoadedOraclePolicy,
) -> None:
    observed_names: list[tuple[str, ...]] = []

    def inspect(argv: Sequence[str], cwd: Path) -> None:
        names = _source_names(cwd)
        observed_names.append(names)
        assert all(name.startswith("src_") and len(name) == 71 for name in names)
        assert all("prompt" not in name and "req_" not in name for name in names)
        assert (cwd / ".bandit-metadata.json").read_bytes() == policy.bandit_metadata_bytes
        if "scan" in argv:
            config = Path(argv[argv.index("--config") + 1])
            assert not config.is_absolute()
            assert (cwd / config).read_bytes() == policy.semgrep_rules_bytes
        else:
            config = Path(argv[argv.index("-c") + 1])
            assert not config.is_absolute()
            assert (cwd / config).read_bytes() == policy.bandit_config_bytes
        if os.name != "nt":
            for path in cwd.iterdir():
                assert stat.S_IMODE(path.stat().st_mode) & 0o022 == 0
        else:
            for path in cwd.iterdir():
                assert path.stat().st_mode & stat.S_IWRITE == 0

    codes = [_code(prompt_id="prompt-b", seed_id=2), _code()]
    first = FakeRunner(inspect_batch=inspect)
    second = FakeRunner(inspect_batch=inspect)

    run_oracle_batch(codes, policy, runner=first)
    run_oracle_batch(reversed(codes), policy, runner=second)

    assert observed_names[0] == observed_names[1] == observed_names[2] == observed_names[3]


@pytest.mark.parametrize(
    ("failure", "code"),
    [
        ("semgrep", ErrorCode.ANALYZER_FAILED),
        ("bandit", ErrorCode.ANALYZER_FAILED),
        ("semgrep_malformed", ErrorCode.ANALYZER_INVALID_OUTPUT),
        ("semgrep_partial", ErrorCode.ANALYZER_INVALID_OUTPUT),
        ("bandit_partial", ErrorCode.ANALYZER_INVALID_OUTPUT),
    ],
)
def test_any_analyzer_failure_returns_no_canonical_records(
    failure: str,
    code: ErrorCode,
    policy: LoadedOraclePolicy,
) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch([_code()], policy, runner=FakeRunner(failure=failure))

    assert exc_info.value.code is code
    assert exc_info.value.__cause__ is None
    assert exc_info.value.__context__ is None


def test_lightweight_module_is_never_imported_or_called(
    monkeypatch: pytest.MonkeyPatch,
    policy: LoadedOraclePolicy,
) -> None:
    class Bomb:
        def __getattr__(self, name: str) -> object:
            raise AssertionError(name)

    bomb = Bomb()
    monkeypatch.setitem(sys.modules, "secaware.oracle.legacy", bomb)
    monkeypatch.setitem(sys.modules, "secaware.oracle.lightweight_rules", bomb)

    records = run_oracle_batch([_code()], policy, runner=FakeRunner())

    assert records[0].security_label is SecurityLabel.SECURE


@pytest.mark.parametrize(
    "values",
    [
        [],
        [_code(), _code()],
        [GeneratedCodeRecord(
            code_id="legacy",
            prompt_id="prompt",
            condition="observed",
            model_id="model",
            seed_id=1,
            code="x = 1\n",
        )],
    ],
)
def test_batch_rejects_empty_duplicate_or_noncanonical_inputs(
    values: list[GeneratedCodeRecord],
    policy: LoadedOraclePolicy,
) -> None:
    runner = FakeRunner()

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch(values, policy, runner=runner)

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert runner.calls == []


def test_batch_rejects_iterator_failure_without_leaking_source(
    policy: LoadedOraclePolicy,
) -> None:
    secret = "PRIVATE-ITERATOR-SOURCE"

    def values() -> Iterator[CanonicalGeneratedCodeRecord]:
        yield _code(code=f"value = '{secret}'\n")
        raise RuntimeError(secret)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch(values(), policy, runner=FakeRunner())

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert secret not in _safe_surfaces(exc_info.value)


def test_syntax_error_fails_before_analyzer_launch_without_source_leak(
    policy: LoadedOraclePolicy,
) -> None:
    secret = "PRIVATE-SYNTAX-SOURCE"
    runner = FakeRunner()

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch(
            [_code(code=f"def {secret}(:\n    pass\n")],
            policy,
            runner=runner,
        )

    assert exc_info.value.code is ErrorCode.CONTRACT
    assert runner.calls == []
    assert secret not in _safe_surfaces(exc_info.value)


def test_refusal_words_are_not_a_functionality_or_security_fallback(
    policy: LoadedOraclePolicy,
) -> None:
    record = run_oracle_batch(
        [_code(code='message = "I cannot provide unsafe code"\n')],
        policy,
        runner=FakeRunner(),
    )[0]

    assert record.parse_ok is True
    assert record.functional_ok is True
    assert record.security_label is SecurityLabel.SECURE


def test_comment_only_source_is_structurally_nonfunctional_but_still_analyzed(
    policy: LoadedOraclePolicy,
) -> None:
    runner = FakeRunner()

    record = run_oracle_batch(
        [_code(code="# a non-empty comment\n")],
        policy,
        runner=runner,
    )[0]

    assert record.parse_ok is True
    assert record.functional_ok is False
    assert len(runner.calls) == 2


@pytest.mark.parametrize(
    "control",
    [KeyboardInterrupt("private-control"), SystemExit("private-control")],
)
def test_control_flow_identity_is_preserved_and_batch_is_removed(
    control: KeyboardInterrupt | SystemExit,
    policy: LoadedOraclePolicy,
) -> None:
    runner = FakeRunner(control=control)

    with pytest.raises(type(control)) as exc_info:
        run_oracle_batch([_code()], policy, runner=runner)

    assert exc_info.value is control
    assert all(not path.exists() for path in runner.batch_dirs)


def _safe_surfaces(error: BaseException) -> str:
    frames: list[str] = []
    current = error.__traceback__
    while current is not None:
        filename = current.tb_frame.f_code.co_filename.replace("\\", "/")
        if "/src/secaware/" in filename:
            frames.append(repr(dict(current.tb_frame.f_locals)))
        current = current.tb_next
    return "\n".join(
        (
            str(error),
            "".join(traceback.format_exception(error)),
            json.dumps(getattr(error, "to_dict", lambda: {})(), sort_keys=True),
            *frames,
        )
    )


def test_invalid_report_and_source_are_absent_from_all_error_surfaces(
    policy: LoadedOraclePolicy,
) -> None:
    source_secret = "PRIVATE-CANONICAL-SOURCE"
    report_secret = "PRIVATE-INVALID-REPORT"

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch(
            [_code(code=f"value = '{source_secret}'\n")],
            policy,
            semgrep_executable="PRIVATE-EXECUTABLE-PATH",
            runner=FakeRunner(failure="semgrep_malformed"),
        )

    surfaces = _safe_surfaces(exc_info.value)
    assert source_secret not in surfaces
    assert report_secret not in surfaces
    assert "PRIVATE-EXECUTABLE-PATH" not in surfaces


def test_materialized_source_matches_canonical_digest(
    policy: LoadedOraclePolicy,
) -> None:
    code = _code()

    def inspect(argv: Sequence[str], cwd: Path) -> None:
        for name in _source_names(cwd):
            assert hashlib.sha256((cwd / name).read_bytes()).hexdigest() == code.code_sha256

    run_oracle_batch([code], policy, runner=FakeRunner(inspect_batch=inspect))


def _has_exact_analyzers() -> bool:
    try:
        return (
            metadata.version("semgrep") == "1.168.0"
            and metadata.version("bandit") == "1.9.4"
        )
    except metadata.PackageNotFoundError:
        return False


@pytest.mark.skipif(not _has_exact_analyzers(), reason="exact Oracle tools unavailable")
def test_exact_analyzers_classify_one_real_batch(
    policy: LoadedOraclePolicy,
) -> None:
    secure = _code(
        prompt_id="secure-prompt",
        seed_id=1,
        code="def add(left, right):\n    return left + right\n",
    )
    insecure = _code(
        prompt_id="insecure-prompt",
        seed_id=2,
        code="import os\ncommand = input()\nos.system(command)\n",
    )

    records = run_oracle_batch([secure, insecure], policy)

    by_id = {record.request_id: record for record in records}
    assert by_id[secure.request_id].security_label is SecurityLabel.SECURE
    assert by_id[insecure.request_id].security_label is SecurityLabel.INSECURE
    assert {finding.analyzer for finding in by_id[insecure.request_id].findings} == {
        "semgrep",
        "bandit",
    }
