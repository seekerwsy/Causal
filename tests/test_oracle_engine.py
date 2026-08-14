from __future__ import annotations

from collections.abc import Callable, Iterator, Sequence
import hashlib
from importlib import metadata
import json
import os
from pathlib import Path
import stat
import traceback

import pytest

from secaware.errors import ErrorCode, SecAwareError
from secaware.generation.result_importer import canonical_generated_code_from_request
from secaware.oracle import aggregator as aggregator_module
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
from secaware.schema.oracle import OracleEvaluability, SecurityLabel
from secaware.schema.records import CanonicalGeneratedCodeRecord, GeneratedCodeRecord


_POLICY_LOCK = Path(__file__).parents[1] / "policies" / "oracle" / "python" / "policy.lock.json"


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
        control_analyzer: str = "semgrep",
        mutation: str | None = None,
        coordinate_case: str | None = None,
        inspect_batch: Callable[[Sequence[str], Path], None] | None = None,
    ) -> None:
        self.finding = finding
        self.failure = failure
        self.control = control
        self.control_analyzer = control_analyzer
        self.mutation = mutation
        self.coordinate_case = coordinate_case
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
        self.calls.append((argv, cwd, timeout_seconds, max_stdout_bytes, max_stderr_bytes))
        self.batch_dirs.append(cwd)
        if self.inspect_batch is not None:
            self.inspect_batch(argv, cwd)
        analyzer = "semgrep" if "scan" in argv else "bandit"
        if analyzer == self.control_analyzer and self.control is not None:
            raise self.control
        if self.mutation == f"{analyzer}_source":
            self._rewrite(cwd / _source_names(cwd)[0], restore=False)
        if self.mutation == f"{analyzer}_source_aba":
            self._rewrite(cwd / _source_names(cwd)[0], restore=True)
        if self.mutation == f"{analyzer}_policy":
            option = "--config" if analyzer == "semgrep" else "-c"
            self._rewrite(cwd / argv[argv.index(option) + 1], restore=False)
        if self.mutation == "bandit_metadata" and analyzer == "bandit":
            self._rewrite(cwd / ".bandit-metadata.json", restore=False)
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
            if results:
                self._mutate_coordinates(analyzer, results[0])
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
        if results:
            self._mutate_coordinates(analyzer, results[0])
        metrics = {filename: {"loc": 3, "nosec": 0, "skipped_tests": 0} for filename in covered}
        metrics["_totals"] = {"loc": 3, "nosec": 0, "skipped_tests": 0}
        payload = {"errors": [], "metrics": metrics, "results": results}
        return AnalyzerProcessResult(
            returncode=1 if results else 0,
            stdout=json.dumps(payload).encode("utf-8"),
            argv_sha256="b" * 64,
        )

    @staticmethod
    def _rewrite(path: Path, *, restore: bool) -> None:
        original = path.read_bytes()
        metadata = path.stat()
        os.chmod(path, stat.S_IREAD | stat.S_IWRITE)
        path.write_bytes(b"X" * len(original))
        if restore:
            path.write_bytes(original)
            os.chmod(path, stat.S_IREAD)
            os.utime(
                path,
                ns=(metadata.st_atime_ns, metadata.st_mtime_ns),
            )

    def _mutate_coordinates(self, analyzer: str, result: dict[str, object]) -> None:
        case = self.coordinate_case
        if case is None:
            return
        if analyzer == "semgrep":
            start = result["start"]
            end = result["end"]
            assert isinstance(start, dict) and isinstance(end, dict)
            if case == "line":
                start.update(line=999, col=1, offset=0)
                end.update(line=999, col=2, offset=1)
            elif case == "column":
                start.update(line=1, col=999, offset=998)
                end.update(line=1, col=1000, offset=999)
            elif case == "unicode_boundary":
                start.update(line=1, col=2, offset=1)
                end.update(line=1, col=4, offset=3)
            elif case == "crlf_offset":
                start.update(line=2, col=1, offset=1)
                end.update(line=2, col=2, offset=2)
            elif case == "empty_line":
                start.update(line=2, col=2, offset=5)
                end.update(line=2, col=3, offset=6)
            elif case == "trailing_line":
                start.update(line=2, col=1, offset=4)
                end.update(line=2, col=1, offset=4)
            elif case == "valid_unicode":
                start.update(line=1, col=1, offset=0)
                end.update(line=1, col=4, offset=3)
            elif case == "valid_crlf":
                start.update(line=2, col=1, offset=5)
                end.update(line=2, col=2, offset=6)
            elif case == "valid_tab":
                start.update(line=2, col=1, offset=9)
                end.update(line=2, col=2, offset=10)
            else:  # pragma: no cover - test fixture guard
                raise AssertionError(case)
        else:
            if case == "line":
                result.update(line_number=999, line_range=[999], col_offset=0, end_col_offset=1)
            elif case == "column":
                result.update(col_offset=998, end_col_offset=999)
            elif case == "unicode_boundary":
                result.update(col_offset=1, end_col_offset=3)
            elif case == "empty_line":
                result.update(line_number=2, line_range=[2], col_offset=1, end_col_offset=2)
            elif case == "trailing_line":
                result.update(line_number=2, line_range=[2], col_offset=0, end_col_offset=0)
            elif case == "valid_unicode":
                result.update(col_offset=0, end_col_offset=3)
            elif case == "valid_tab":
                result.update(
                    line_number=2,
                    line_range=[2],
                    col_offset=0,
                    end_col_offset=1,
                )
            else:  # pragma: no cover - test fixture guard
                raise AssertionError(case)


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


def test_both_clean_reports_produce_unknown_coverage_and_run_each_tool_once(
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
    assert runner.calls[0][1] != runner.calls[1][1]
    assert all(call[2:] == (7.5, 8192, 2048) for call in runner.calls)
    assert runner.calls[0][0][-1] == "."
    assert runner.calls[1][0][2] == "."
    assert [record.request_id for record in records] == sorted(code.request_id for code in codes)
    assert all(record.security_label is SecurityLabel.UNKNOWN for record in records)
    assert all(
        record.evaluability is OracleEvaluability.UNKNOWN_COVERAGE for record in records
    )
    assert all(record.severity == "none" for record in records)
    assert all(record.findings == () for record in records)
    assert all(
        tuple(item.analyzer for item in record.analyzers) == ("semgrep", "bandit")
        for record in records
    )
    assert all(
        {item.policy_sha256 for item in record.analyzers} == {policy.combined_sha256}
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
        if "scan" in argv:
            config = Path(argv[argv.index("--config") + 1])
            assert not config.is_absolute()
            assert (cwd / config).read_bytes() == policy.semgrep_rules_bytes
            assert not (cwd / ".bandit-policy.json").exists()
            assert not (cwd / ".bandit-metadata.json").exists()
        else:
            config = Path(argv[argv.index("-c") + 1])
            assert not config.is_absolute()
            assert (cwd / config).read_bytes() == policy.bandit_config_bytes
            assert (cwd / ".bandit-metadata.json").read_bytes() == policy.bandit_metadata_bytes
            assert not (cwd / ".semgrep-policy.yml").exists()
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


@pytest.mark.parametrize(
    "values",
    [
        [],
        [_code(), _code()],
        [
            GeneratedCodeRecord(
                code_id="legacy",
                prompt_id="prompt",
                condition="observed",
                model_id="model",
                seed_id=1,
                code="x = 1\n",
            )
        ],
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


def test_completed_syntax_error_is_typed_unknown_without_source_leak(
    policy: LoadedOraclePolicy,
) -> None:
    secret = "PRIVATE-SYNTAX-SOURCE"
    runner = FakeRunner()

    record = run_oracle_batch(
        [_code(code=f"def {secret}(:\n    pass\n")],
        policy,
        runner=runner,
    )[0]

    assert len(runner.calls) == 2
    assert record.parse_ok is False
    assert record.functional_ok is False
    assert record.security_label is SecurityLabel.UNKNOWN
    assert record.evaluability is OracleEvaluability.UNKNOWN_PARSE_FAILURE


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
    assert record.security_label is SecurityLabel.UNKNOWN
    assert record.evaluability is OracleEvaluability.UNKNOWN_COVERAGE


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
@pytest.mark.parametrize("control_analyzer", ["semgrep", "bandit"])
def test_control_flow_identity_is_preserved_and_batch_is_removed(
    control: KeyboardInterrupt | SystemExit,
    control_analyzer: str,
    policy: LoadedOraclePolicy,
) -> None:
    runner = FakeRunner(control=control, control_analyzer=control_analyzer)

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


@pytest.mark.parametrize(
    "mutation",
    [
        "semgrep_source",
        "semgrep_source_aba",
        "semgrep_policy",
        "bandit_source",
        "bandit_source_aba",
        "bandit_policy",
        "bandit_metadata",
    ],
)
def test_material_drift_never_produces_an_oracle_record(
    mutation: str,
    policy: LoadedOraclePolicy,
) -> None:
    runner = FakeRunner(mutation=mutation)

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch([_code()], policy, runner=runner)

    assert exc_info.value.code in {
        ErrorCode.ANALYZER_FAILED,
        ErrorCode.ANALYZER_INVALID_OUTPUT,
    }
    assert all(not path.exists() for path in runner.batch_dirs)


@pytest.mark.skipif(os.name == "nt", reason="Windows ABA is prevented by material leases")
def test_linux_post_seal_detects_byte_and_mtime_restored_aba(
    monkeypatch: pytest.MonkeyPatch,
    policy: LoadedOraclePolicy,
) -> None:
    monkeypatch.setattr(
        aggregator_module,
        "_open_windows_material_leases",
        lambda batch: aggregator_module._WindowsMaterialLeases([], None),
    )

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch(
            [_code()],
            policy,
            runner=FakeRunner(mutation="semgrep_source_aba"),
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_INVALID_OUTPUT


def test_coordinate_failure_does_not_leak_source(
    policy: LoadedOraclePolicy,
) -> None:
    secret = "PRIVATE-COORDINATE-SOURCE"

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch(
            [_code(code=f"前 = '{secret}'\n")],
            policy,
            runner=FakeRunner(finding="semgrep", coordinate_case="unicode_boundary"),
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_INVALID_OUTPUT
    assert secret not in _safe_surfaces(exc_info.value)


@pytest.mark.parametrize("first_failure", ["false", "raise"])
def test_windows_material_lease_retains_failed_handles_for_idempotent_retry(
    first_failure: str,
) -> None:
    class Kernel32:
        def __init__(self) -> None:
            self.calls: list[int] = []
            self.closed: list[int] = []

        def CloseHandle(self, handle: int) -> bool:
            self.calls.append(handle)
            if len(self.calls) == 1:
                if first_failure == "raise":
                    raise OSError("private-close-error")
                return False
            self.closed.append(handle)
            return True

    kernel32 = Kernel32()
    leases = aggregator_module._WindowsMaterialLeases([101, 202], kernel32)

    with pytest.raises(OSError):
        leases.close()

    assert leases.handles == [101]
    assert leases.kernel32 is kernel32

    leases.close()

    assert leases.handles == []
    assert leases.kernel32 is None
    assert kernel32.closed == [202, 101]
    leases.close()


@pytest.mark.parametrize("first_failure", ["false", "raise"])
@pytest.mark.parametrize("runner_outcome", ["ordinary", "keyboard", "system"])
def test_bounded_lease_cleanup_retries_after_runner_failure_or_control(
    first_failure: str,
    runner_outcome: str,
    monkeypatch: pytest.MonkeyPatch,
    policy: LoadedOraclePolicy,
) -> None:
    kernels: list[object] = []
    leases_seen: list[object] = []

    class Kernel32:
        def __init__(self) -> None:
            self.calls = 0
            self.closed: set[int] = set()

        def CloseHandle(self, handle: int) -> bool:
            self.calls += 1
            if self.calls == 1:
                if first_failure == "raise":
                    raise OSError("private-close-error")
                return False
            self.closed.add(handle)
            return True

    def lease_factory(batch: object) -> object:
        del batch
        kernel = Kernel32()
        leases = aggregator_module._WindowsMaterialLeases([101, 202], kernel)
        kernels.append(kernel)
        leases_seen.append(leases)
        return leases

    monkeypatch.setattr(
        aggregator_module,
        "_open_windows_material_leases",
        lease_factory,
    )
    control: KeyboardInterrupt | SystemExit | None = None
    if runner_outcome == "keyboard":
        control = KeyboardInterrupt("private-runner-control")
    elif runner_outcome == "system":
        control = SystemExit("private-runner-control")
    runner = FakeRunner(
        failure="semgrep" if runner_outcome == "ordinary" else None,
        control=control,
    )

    if control is None:
        with pytest.raises(SecAwareError) as exc_info:
            run_oracle_batch([_code()], policy, runner=runner)
        assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    else:
        with pytest.raises(type(control)) as exc_info:
            run_oracle_batch([_code()], policy, runner=runner)
        assert exc_info.value is control

    assert len(kernels) == 1
    assert kernels[0].closed == {101, 202}  # type: ignore[attr-defined]
    assert leases_seen[0].handles == []  # type: ignore[attr-defined]
    assert all(not path.exists() for path in runner.batch_dirs)


def test_persistent_lease_cleanup_is_bounded_and_returns_only_safe_failure(
    monkeypatch: pytest.MonkeyPatch,
    policy: LoadedOraclePolicy,
) -> None:
    secret = "persistent-private-close-error"
    leases_seen: list[object] = []

    class Kernel32:
        def __init__(self) -> None:
            self.calls = 0

        def CloseHandle(self, handle: int) -> bool:
            del handle
            self.calls += 1
            raise OSError(secret)

    kernel = Kernel32()

    def lease_factory(batch: object) -> object:
        del batch
        leases = aggregator_module._WindowsMaterialLeases([101, 202], kernel)
        leases_seen.append(leases)
        return leases

    monkeypatch.setattr(
        aggregator_module,
        "_open_windows_material_leases",
        lease_factory,
    )
    runner = FakeRunner()

    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch([_code()], policy, runner=runner)

    assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
    assert exc_info.value.details == {}
    assert secret not in _safe_surfaces(exc_info.value)
    assert kernel.calls == 2 * aggregator_module._MAX_CLEANUP_ATTEMPTS
    assert leases_seen[0].handles == [101, 202]  # type: ignore[attr-defined]
    assert all(not path.exists() for path in runner.batch_dirs)


@pytest.mark.parametrize("cleanup_outcome", ["ordinary", "keyboard", "system"])
def test_bounded_rmtree_cleanup_retries_and_preserves_control_identity(
    cleanup_outcome: str,
    monkeypatch: pytest.MonkeyPatch,
    policy: LoadedOraclePolicy,
) -> None:
    original_remove = aggregator_module._remove_batch_tree
    cleanup_control: KeyboardInterrupt | SystemExit | None = None
    if cleanup_outcome == "keyboard":
        cleanup_control = KeyboardInterrupt("private-cleanup-control")
    elif cleanup_outcome == "system":
        cleanup_control = SystemExit("private-cleanup-control")
    calls = 0

    def flaky_remove(root: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            if cleanup_control is not None:
                raise cleanup_control
            raise OSError("private-rmtree-error")
        original_remove(root)

    monkeypatch.setattr(aggregator_module, "_remove_batch_tree", flaky_remove)
    runner = FakeRunner()

    if cleanup_control is None:
        records = run_oracle_batch([_code()], policy, runner=runner)
        assert records[0].security_label is SecurityLabel.UNKNOWN
        assert records[0].evaluability is OracleEvaluability.UNKNOWN_COVERAGE
    else:
        with pytest.raises(type(cleanup_control)) as exc_info:
            run_oracle_batch([_code()], policy, runner=runner)
        assert exc_info.value is cleanup_control

    assert calls >= 2
    assert all(not path.exists() for path in runner.batch_dirs)


@pytest.mark.parametrize("runner_control", [False, True])
def test_persistent_rmtree_failure_is_bounded_and_fail_closed(
    runner_control: bool,
    monkeypatch: pytest.MonkeyPatch,
    policy: LoadedOraclePolicy,
) -> None:
    original_remove = aggregator_module._remove_batch_tree
    secret = "persistent-private-rmtree-error"
    control = KeyboardInterrupt("private-runner-control") if runner_control else None
    calls = 0

    def failing_remove(root: Path) -> None:
        nonlocal calls
        del root
        calls += 1
        raise OSError(secret)

    monkeypatch.setattr(aggregator_module, "_remove_batch_tree", failing_remove)
    runner = FakeRunner(control=control)
    try:
        if control is None:
            with pytest.raises(SecAwareError) as exc_info:
                run_oracle_batch([_code()], policy, runner=runner)
            assert exc_info.value.code is ErrorCode.ANALYZER_FAILED
            assert exc_info.value.details == {}
            assert secret not in _safe_surfaces(exc_info.value)
        else:
            with pytest.raises(KeyboardInterrupt) as exc_info:
                run_oracle_batch([_code()], policy, runner=runner)
            assert exc_info.value is control
            cleanup_status = getattr(
                control,
                "__notes__",
                getattr(control, aggregator_module._CLEANUP_STATUS_ATTRIBUTE, ()),
            )
            assert aggregator_module._CLEANUP_INCOMPLETE_NOTE in cleanup_status

        assert calls == aggregator_module._MAX_CLEANUP_ATTEMPTS
        assert runner.batch_dirs and all(path.exists() for path in runner.batch_dirs)
    finally:
        for root in runner.batch_dirs:
            original_remove(root)


def test_runner_control_wins_over_cleanup_control_and_cleanup_still_finishes(
    monkeypatch: pytest.MonkeyPatch,
    policy: LoadedOraclePolicy,
) -> None:
    original_remove = aggregator_module._remove_batch_tree
    runner_control = KeyboardInterrupt("private-runner-control")
    cleanup_control = SystemExit("private-cleanup-control")
    calls = 0

    def flaky_remove(root: Path) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise cleanup_control
        original_remove(root)

    monkeypatch.setattr(aggregator_module, "_remove_batch_tree", flaky_remove)
    runner = FakeRunner(control=runner_control)

    with pytest.raises(KeyboardInterrupt) as exc_info:
        run_oracle_batch([_code()], policy, runner=runner)

    assert exc_info.value is runner_control
    cleanup_status = getattr(
        runner_control,
        "__notes__",
        getattr(
            runner_control,
            aggregator_module._CLEANUP_STATUS_ATTRIBUTE,
            (),
        ),
    )
    assert aggregator_module._CLEANUP_CONTROL_NOTE in cleanup_status
    assert calls >= 2
    assert all(not path.exists() for path in runner.batch_dirs)


@pytest.mark.skipif(os.name != "nt", reason="Windows-only deny-delete verification")
def test_real_windows_material_lease_denies_delete_until_closed(
    policy: LoadedOraclePolicy,
) -> None:
    validated = aggregator_module._snapshot_codes([_code()])
    trusted_policy = aggregator_module._snapshot_policy(policy)
    batch = aggregator_module._materialize_batch(validated, trusted_policy, "semgrep")
    leases = aggregator_module._open_windows_material_leases(batch)
    material = batch.root / batch.materials[0].name
    try:
        with pytest.raises(OSError):
            material.unlink()
    finally:
        leases.close()
        aggregator_module._remove_batch_tree(batch.root)

    assert not batch.root.exists()


def test_analyzers_receive_independent_batches_with_identical_sources(
    policy: LoadedOraclePolicy,
) -> None:
    code = _code()
    batch_roots: list[Path] = []

    def inspect(argv: Sequence[str], cwd: Path) -> None:
        batch_roots.append(cwd)
        assert (cwd / _source_names(cwd)[0]).read_text(encoding="utf-8") == code.code

    records = run_oracle_batch(
        [code],
        policy,
        runner=FakeRunner(inspect_batch=inspect),
    )

    assert records[0].security_label is SecurityLabel.UNKNOWN
    assert records[0].evaluability is OracleEvaluability.UNKNOWN_COVERAGE
    assert len(batch_roots) == 2
    assert batch_roots[0] != batch_roots[1]
    assert all(not root.exists() for root in batch_roots)


@pytest.mark.parametrize(
    ("analyzer", "case", "source"),
    [
        ("semgrep", "line", "x = 1\n"),
        ("bandit", "line", "x = 1\n"),
        ("semgrep", "column", "x = 1\n"),
        ("bandit", "column", "x = 1\n"),
        ("semgrep", "unicode_boundary", "前 = 1\n"),
        ("bandit", "unicode_boundary", "前 = 1\n"),
        ("semgrep", "crlf_offset", "x=1\r\ny=2\r\n"),
        ("semgrep", "empty_line", "x=1\n\nz=2\n"),
        ("bandit", "empty_line", "x=1\n\nz=2\n"),
        ("semgrep", "trailing_line", "x=1\n"),
        ("bandit", "trailing_line", "x=1\n"),
    ],
)
def test_findings_must_be_real_utf8_source_boundaries(
    analyzer: str,
    case: str,
    source: str,
    policy: LoadedOraclePolicy,
) -> None:
    with pytest.raises(SecAwareError) as exc_info:
        run_oracle_batch(
            [_code(code=source)],
            policy,
            runner=FakeRunner(finding=analyzer, coordinate_case=case),
        )

    assert exc_info.value.code is ErrorCode.ANALYZER_INVALID_OUTPUT


@pytest.mark.parametrize(
    ("analyzer", "case", "source"),
    [
        ("semgrep", "valid_unicode", "前 = 1\n"),
        ("bandit", "valid_unicode", "前 = 1\n"),
        ("semgrep", "valid_crlf", "x=1\r\ny=2\r\n"),
        ("bandit", "valid_tab", "if True:\n\tvalue = 1\n"),
    ],
)
def test_valid_unicode_crlf_and_tab_boundaries_are_accepted(
    analyzer: str,
    case: str | None,
    source: str,
    policy: LoadedOraclePolicy,
) -> None:
    record = run_oracle_batch(
        [_code(code=source)],
        policy,
        runner=FakeRunner(finding=analyzer, coordinate_case=case),
    )[0]

    assert record.security_label is SecurityLabel.INSECURE
    assert record.findings[0].analyzer == analyzer


def _has_exact_analyzers() -> bool:
    try:
        return metadata.version("semgrep") == "1.168.0" and metadata.version("bandit") == "1.9.4"
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
        code=('import os\r\ncommand = input()\r\n前缀 = "值"; os.system(command)\r\n'),
    )

    records = run_oracle_batch([secure, insecure], policy)

    by_id = {record.request_id: record for record in records}
    assert by_id[secure.request_id].security_label is SecurityLabel.UNKNOWN
    assert (
        by_id[secure.request_id].evaluability is OracleEvaluability.UNKNOWN_COVERAGE
    )
    assert by_id[insecure.request_id].security_label is SecurityLabel.INSECURE
    assert {finding.analyzer for finding in by_id[insecure.request_id].findings} == {
        "semgrep",
        "bandit",
    }
