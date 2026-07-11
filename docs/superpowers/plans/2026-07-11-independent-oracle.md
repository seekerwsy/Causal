# Independent Static-Analysis Oracle Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the in-process security rules with a fail-closed, version- and policy-locked Oracle that requires successful Semgrep and Bandit analysis.

**Architecture:** A strict policy loader authenticates checked-in analyzer policy files and exact tool versions. A bounded subprocess runner executes both analyzers once over an opaque temporary batch, dedicated adapters normalize their JSON, and a pure aggregator emits immutable Oracle records only after both reports validate. CLI stages use the existing output-seal, manifest, producer-commit, and OS-lease machinery.

**Tech Stack:** Python 3.10+, Pydantic 2, Typer, Semgrep 1.168.0, Bandit 1.9.4, pytest, stdlib subprocess/tempfile/hashlib.

---

## File map

- `src/secaware/schema/oracle.py`: immutable policy, finding, analyzer report, and canonical Oracle schemas.
- `src/secaware/oracle/policy.py`: policy-lock loading, hash verification, and version matching.
- `src/secaware/oracle/runner.py`: bounded, shell-free external process runner.
- `src/secaware/oracle/semgrep_adapter.py`: Semgrep argv and strict JSON normalization.
- `src/secaware/oracle/bandit_adapter.py`: Bandit argv and strict JSON normalization.
- `src/secaware/oracle/aggregator.py`: pure two-analyzer aggregation and batch engine.
- `src/secaware/oracle/functionality.py`: syntax/structure-only functionality status.
- `src/secaware/oracle/cli.py`: standalone Oracle command.
- `src/secaware/config.py`, `src/secaware/pipeline/preflight.py`, `src/secaware/cli.py`: fail-closed configuration and pipeline integration.
- `src/secaware/io/run_store.py`, `src/secaware/pipeline/manifest.py`: policy digest binding.
- `policies/oracle/python/*`: checked-in finite policy bundle and lock.
- `tests/test_oracle_*.py`: schema, policy, runner, adapter, engine, CLI, and publication tests.

### Task 1: Strict Oracle schemas and configuration

**Files:**
- Create: `src/secaware/schema/oracle.py`
- Modify: `src/secaware/schema/results.py`
- Modify: `src/secaware/schema/__init__.py`
- Modify: `src/secaware/config.py`
- Test: `tests/test_oracle_schema_v1.py`

- [ ] **Step 1: Write failing schema tests**

```python
def test_oracle_record_requires_analyzer_provenance_and_request_binding():
    record = OracleRecord.model_validate(_canonical_oracle_payload())
    assert record.schema_version == "1.0"
    assert record.request_id.startswith("req_")
    assert {item.analyzer for item in record.analyzers} == {"semgrep", "bandit"}


def test_oracle_config_has_no_lightweight_switches():
    with pytest.raises(ValidationError):
        OracleConfig.model_validate({"use_lightweight_rules": True})
```

- [ ] **Step 2: Run the tests and verify RED**

Run: `pytest -q tests/test_oracle_schema_v1.py`

Expected: collection or validation failures because the new schemas and fail-closed configuration do not exist.

- [ ] **Step 3: Implement immutable schemas and config**

```python
class AnalyzerFindingRecord(SafeValidationMixin, VersionedModel):
    model_config = ConfigDict(extra="forbid", frozen=True, revalidate_instances="always")
    schema_version: Literal["1.0"]
    analyzer: Literal["semgrep", "bandit"]
    rule_id: str = Field(min_length=1, max_length=256)
    cwe: str = Field(min_length=1, max_length=32)
    severity: Literal["low", "medium", "high"]
    confidence: Literal["low", "medium", "high", "not_provided"]
    line: int = Field(ge=1)
    column: int = Field(ge=1)
    end_line: int = Field(ge=1)
    end_column: int = Field(ge=1)
    message: str = Field(min_length=1, max_length=4096)


class AnalyzerProvenanceRecord(SafeValidationMixin, VersionedModel):
    schema_version: Literal["1.0"]
    analyzer: Literal["semgrep", "bandit"]
    version: str
    policy_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class OracleConfig(SafeValidationMixin, StrictModel):
    language: Literal["python"] = "python"
    policy_lock_path: str = "policies/oracle/python/policy.lock.json"
    semgrep_executable: str = "semgrep"
    bandit_executable: str = "bandit"
    timeout_seconds: float = Field(default=120.0, gt=0, le=3600)
    max_stdout_bytes: int = Field(default=64 * 1024 * 1024, ge=1024, le=256 * 1024 * 1024)
    max_stderr_bytes: int = Field(default=4 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
```

`OracleRecord` must be versioned, frozen, safe on every validation surface, bind `request_id`, `code_sha256`, and all existing pairing coordinates, and require exactly one Semgrep and one Bandit provenance record.

- [ ] **Step 4: Re-run schema tests**

Run: `pytest -q tests/test_oracle_schema_v1.py tests/test_config_v1.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secaware/schema src/secaware/config.py tests/test_oracle_schema_v1.py tests/test_config_v1.py
git commit -m "feat: add strict oracle contracts"
```

### Task 2: Authenticated policy bundle

**Files:**
- Create: `src/secaware/oracle/policy.py`
- Create: `policies/oracle/python/semgrep.yml`
- Create: `policies/oracle/python/bandit.yml`
- Create: `policies/oracle/python/policy.lock.json`
- Test: `tests/test_oracle_policy.py`

- [ ] **Step 1: Write failing policy tests**

```python
def test_policy_bundle_requires_exact_hashes_and_versions(tmp_path):
    bundle = load_policy_bundle(_write_locked_policy(tmp_path))
    assert bundle.semgrep_version == "1.168.0"
    assert bundle.bandit_version == "1.9.4"
    assert bundle.combined_sha256 == canonical_sha256(bundle.lock_payload)


def test_changed_policy_is_a_hard_failure(tmp_path):
    lock = _write_locked_policy(tmp_path)
    lock.parent.joinpath("semgrep.yml").write_text("rules: []\n", encoding="utf-8")
    with pytest.raises(SecAwareError) as error:
        load_policy_bundle(lock)
    assert error.value.code is ErrorCode.POLICY_MISMATCH
```

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/test_oracle_policy.py`

Expected: FAIL because no policy loader or bundle exists.

- [ ] **Step 3: Implement the strict lock and finite policy**

```python
class OraclePolicyLock(SafeValidationMixin, VersionedModel):
    schema_version: Literal["1.0"]
    policy_name: str
    language: Literal["python"]
    semgrep_version: Literal["1.168.0"]
    bandit_version: Literal["1.9.4"]
    semgrep_rules: str
    semgrep_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    bandit_config: str
    bandit_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
```

Resolve both policy paths relative to the lock, reject absolute paths and symlinks, verify containment and exact file digests, and return only resolved paths plus typed metadata. The Semgrep file contains a finite reviewed Python policy for command injection, SQL injection, unsafe deserialization, and path traversal. The Bandit file configures Bandit's analyzer tests and excludes only the temporary output directory metadata, not security tests.

- [ ] **Step 4: Verify policy tests and checked-in lock**

Run: `pytest -q tests/test_oracle_policy.py`

Expected: PASS, including checked-in bundle hash verification.

- [ ] **Step 5: Commit**

```bash
git add src/secaware/oracle/policy.py policies/oracle/python tests/test_oracle_policy.py
git commit -m "feat: add locked oracle policy bundle"
```

### Task 3: Bounded external runner

**Files:**
- Create: `src/secaware/oracle/runner.py`
- Test: `tests/test_oracle_runner.py`

- [ ] **Step 1: Write failing runner tests**

```python
def test_runner_uses_argv_without_shell_and_bounds_output(fake_executable, tmp_path):
    result = run_analyzer_process(
        [str(fake_executable), "--json"],
        cwd=tmp_path,
        timeout_seconds=2.0,
        max_stdout_bytes=4096,
        max_stderr_bytes=1024,
    )
    assert result.argv_sha256
    assert result.stdout == b'{"ok":true}\n'


@pytest.mark.parametrize("mode", ["missing", "timeout", "oversized", "signal"])
def test_runner_fails_closed_without_raw_output(mode, runner_cases):
    with pytest.raises(SecAwareError) as error:
        runner_cases.run(mode)
    assert error.value.code in {ErrorCode.ANALYZER_MISSING, ErrorCode.ANALYZER_FAILED,
                                ErrorCode.ANALYZER_INVALID_OUTPUT}
```

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/test_oracle_runner.py`

Expected: FAIL because the bounded runner is missing.

- [ ] **Step 3: Implement the runner**

```python
@dataclass(frozen=True, slots=True, repr=False)
class AnalyzerProcessResult:
    returncode: int
    stdout: bytes
    argv_sha256: str


def run_analyzer_process(
    argv: Sequence[str], *, cwd: Path, timeout_seconds: float,
    max_stdout_bytes: int, max_stderr_bytes: int,
) -> AnalyzerProcessResult:
    argv_tuple = validate_analyzer_argv(argv)
    executable = resolve_analyzer_executable(argv_tuple[0])
    return run_resolved_process(
        (str(executable), *argv_tuple[1:]),
        cwd=cwd,
        timeout_seconds=timeout_seconds,
        max_stdout_bytes=max_stdout_bytes,
        max_stderr_bytes=max_stderr_bytes,
    )
```

`run_resolved_process` calls `subprocess.Popen` with `shell=False`, `stdin=DEVNULL`, the
validated tuple as argv, bounded temporary stdout/stderr files, and the minimal environment.
It kills and waits after timeout, checks output file sizes before reading, and preserves
`KeyboardInterrupt` and `SystemExit` identities while cleaning child processes and direct frame
locals.

- [ ] **Step 4: Re-run runner tests**

Run: `pytest -q tests/test_oracle_runner.py`

Expected: PASS on Windows and POSIX paths.

- [ ] **Step 5: Commit**

```bash
git add src/secaware/oracle/runner.py tests/test_oracle_runner.py
git commit -m "feat: add bounded analyzer runner"
```

### Task 4: Semgrep and Bandit adapters

**Files:**
- Replace: `src/secaware/oracle/semgrep_adapter.py`
- Replace: `src/secaware/oracle/bandit_adapter.py`
- Test: `tests/test_semgrep_adapter.py`
- Test: `tests/test_bandit_adapter.py`

- [ ] **Step 1: Write failing adapter tests**

```python
def test_semgrep_normalizes_findings_and_requires_full_coverage():
    report = parse_semgrep_report(_semgrep_json(), expected_files={"code_a.py"})
    assert report.findings[0].analyzer == "semgrep"
    assert report.findings[0].cwe == "CWE-78"


def test_bandit_exit_one_with_findings_is_success():
    report = parse_bandit_report(_bandit_json(), returncode=1,
                                 expected_files={"code_a.py"})
    assert report.findings[0].analyzer == "bandit"
```

Add parameterized RED tests for malformed JSON, wrong types, analyzer `errors`, foreign paths, missing coverage, duplicate/invalid locations, unknown severity, oversized messages, and unexpected exit statuses.

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/test_semgrep_adapter.py tests/test_bandit_adapter.py`

Expected: FAIL because both files are stubs.

- [ ] **Step 3: Implement exact argv and strict parsers**

```python
def semgrep_argv(executable: Path, policy: Path, target: Path) -> tuple[str, ...]:
    return (str(executable), "scan", "--json", "--metrics=off",
            "--disable-version-check", "--no-git-ignore", "--jobs=1",
            "--config", str(policy), str(target))


def bandit_argv(executable: Path, config: Path, target: Path) -> tuple[str, ...]:
    return (str(executable), "-r", str(target), "-f", "json", "-c", str(config))
```

Parse JSON from bytes with an explicit size already enforced by the runner. Do not retain raw snippets or analyzer output. Normalize and sort findings by analyzer, opaque file, location, and rule ID. Semgrep must have exit 0 and no errors. Bandit accepts only exit 0 or 1 and must have an empty `errors` list.

- [ ] **Step 4: Re-run adapter tests**

Run: `pytest -q tests/test_semgrep_adapter.py tests/test_bandit_adapter.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secaware/oracle/semgrep_adapter.py src/secaware/oracle/bandit_adapter.py tests/test_semgrep_adapter.py tests/test_bandit_adapter.py
git commit -m "feat: normalize required analyzer reports"
```

### Task 5: Batch Oracle engine and aggregation

**Files:**
- Replace: `src/secaware/oracle/aggregator.py`
- Modify: `src/secaware/oracle/functionality.py`
- Modify: `src/secaware/oracle/__init__.py`
- Test: `tests/test_oracle_engine.py`
- Modify: `tests/test_oracle.py`

- [ ] **Step 1: Write failing engine tests**

```python
def test_both_clean_reports_produce_secure_records(fake_runner, canonical_codes):
    records = run_oracle_batch(canonical_codes, _policy(), runner=fake_runner)
    assert all(record.security_label is SecurityLabel.SECURE for record in records)


def test_either_analyzer_finding_produces_insecure():
    records = run_oracle_batch(_codes(), _policy(), runner=_runner(semgrep_finding=True))
    assert records[0].security_label is SecurityLabel.INSECURE


@pytest.mark.parametrize("failure", ["semgrep_missing", "bandit_timeout",
                                      "parse_error", "partial_coverage"])
def test_oracle_never_falls_back(failure, monkeypatch):
    monkeypatch.setitem(sys.modules, "secaware.oracle.lightweight_rules", _bomb_module())
    with pytest.raises(SecAwareError):
        run_oracle_batch(_codes(), _policy(), runner=_runner(failure=failure))
```

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/test_oracle_engine.py tests/test_oracle.py`

Expected: FAIL because the old aggregator imports lightweight rules and has no batch engine.

- [ ] **Step 3: Implement the batch engine**

```python
def run_oracle_batch(
    codes: Iterable[CanonicalGeneratedCodeRecord],
    policy: LoadedOraclePolicy,
    *, runner: AnalyzerRunner = run_analyzer_process,
) -> list[OracleRecord]:
    validated = validate_oracle_inputs(codes)
    with materialize_oracle_batch(validated) as batch:
        reports = run_required_analyzers(batch, policy, runner=runner)
    return aggregate_oracle_reports(validated, reports, policy)
```

`evaluate_functionality` must use only `ast.parse`, non-empty content, and presence of a Python statement. Remove refusal markers and all security finding logic. Reject syntax errors for the Oracle stage instead of emitting `unknown`.

- [ ] **Step 4: Re-run engine tests**

Run: `pytest -q tests/test_oracle_engine.py tests/test_oracle.py`

Expected: PASS, and `rg "lightweight_rules" src/secaware/oracle/aggregator.py` returns no matches.

- [ ] **Step 5: Commit**

```bash
git add src/secaware/oracle tests/test_oracle_engine.py tests/test_oracle.py
git commit -m "feat: add fail-closed oracle engine"
```

### Task 6: Pipeline, manifests, preflight, and standalone CLI

**Files:**
- Modify: `src/secaware/pipeline/manifest.py`
- Modify: `src/secaware/io/run_store.py`
- Modify: `src/secaware/pipeline/preflight.py`
- Modify: `src/secaware/cli.py`
- Replace: `src/secaware/oracle/cli.py`
- Modify: `configs/demo.yaml`
- Modify: `configs/paper_v0.yaml`
- Test: `tests/test_oracle_cli.py`
- Modify: `tests/test_stage_manifest.py`
- Modify: `tests/test_preflight.py`
- Modify: `tests/test_run_all_demo.py`

- [ ] **Step 1: Write failing stage and CLI tests**

```python
def test_oracle_stage_binds_policy_digest_and_publishes_after_both_tools(
    oracle_stage_fixture,
):
    config, store, fake_runner, loaded_policy = oracle_stage_fixture
    run_oracle_stage(
        config, store, condition="observed", force=False, runner=fake_runner
    )
    manifest = read_stage_manifest(store.path(".stages", "run-oracle-observed.json"))
    assert manifest.policy_sha256 == loaded_policy.combined_sha256


def test_second_analyzer_failure_leaves_no_committed_oracle(oracle_stage_fixture):
    config, store, _, _ = oracle_stage_fixture
    with pytest.raises(SecAwareError) as error:
        run_oracle_stage(
            config,
            store,
            condition="observed",
            force=False,
            runner=bandit_failure_runner,
        )
    assert error.value.code is ErrorCode.ANALYZER_FAILED
    assert not store.path(".stages", "run-oracle-observed.json").exists()


def test_oracle_preflight_fails_closed_before_analyzer_resolution(
    oracle_stage_fixture, monkeypatch
):
    config, store, _, _ = oracle_stage_fixture
    monkeypatch.setattr(
        "secaware.oracle.runner.validate_analyzer_runtime",
        forced_unsupported_runtime,
    )
    with pytest.raises(SecAwareError) as error:
        run_oracle_stage(config, store, condition="observed", force=False)
    assert error.value.code is ErrorCode.ANALYZER_FAILED
    assert analyzer_launches == []
```

Add CLI tests for missing binaries, version mismatch, policy mismatch, invalid output, condition validation, standalone input/output, force/skip, producer manifest checks, output tampering, and safe error surfaces.

- [ ] **Step 2: Verify RED**

Run: `pytest -q tests/test_oracle_cli.py tests/test_stage_manifest.py tests/test_preflight.py tests/test_run_all_demo.py`

Expected: FAIL because policy-aware manifests and the real Oracle CLI do not exist.

- [ ] **Step 3: Bind policy digests and integrate the engine**

Add `policy_sha256: str | None` to `StageManifest` and `_StageSnapshot`; include it in fingerprint construction, skip validation, record validation, and readback. The Oracle-specific preflight calls `validate_analyzer_runtime()` before resolving or version-checking analyzers. `run_oracle_stage` calls it again immediately before execution, authenticates the committed generated-code producer, loads the policy, verifies versions, runs the batch engine, atomically writes and seals Oracle JSONL, strictly reads it back, and records the policy-bound manifest. Unsupported Windows/Linux capabilities, non-Linux POSIX systems, and all other platforms fail closed with `ANALYZER_FAILED`; the general package preflight remains platform-independent.

The standalone command shape is:

```text
secaware-oracle run --input CODE.jsonl --output ORACLE.jsonl \
  --policy-lock policies/oracle/python/policy.lock.json \
  --semgrep semgrep --bandit bandit
```

It uses the same canonical schemas and engine. It does not accept a lightweight mode.

- [ ] **Step 4: Re-run integration tests**

Run: `pytest -q tests/test_oracle_cli.py tests/test_stage_manifest.py tests/test_preflight.py tests/test_run_all_demo.py`

Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add src/secaware/cli.py src/secaware/oracle/cli.py src/secaware/pipeline src/secaware/io/run_store.py src/secaware/pipeline/preflight.py configs tests
git commit -m "feat: connect policy-locked oracle CLI"
```

### Task 7: Exact-tool integration gate and legacy removal

**Files:**
- Modify: `pyproject.toml`
- Delete: `src/secaware/oracle/lightweight_rules.py`
- Create: `tests/oracle_corpus/secure.py`
- Create: `tests/oracle_corpus/insecure.py`
- Create: `tests/test_oracle_real_tools.py`
- Modify: `README.md`

- [ ] **Step 1: Add the exact optional dependency and failing corpus test**

```toml
[project.optional-dependencies]
oracle = [
  "semgrep==1.168.0",
  "bandit==1.9.4",
]
```

```python
@pytest.mark.oracle_tools
def test_locked_real_tools_classify_corpus():
    records = run_oracle_batch(_corpus_records(), load_policy_bundle(POLICY_LOCK))
    assert [record.security_label for record in records] == [
        SecurityLabel.SECURE, SecurityLabel.INSECURE,
    ]
```

- [ ] **Step 2: Verify the test is gated without the extra**

Run: `pytest -q tests/test_oracle_real_tools.py`

Expected: SKIP with an explicit exact-tool-unavailable reason, not PASS through a fallback.

- [ ] **Step 3: Remove the old rule module and document installation**

Delete `lightweight_rules.py`, remove all imports and config keys, and document:

```text
uv sync --extra oracle
secaware preflight --config configs/demo.yaml
secaware run-oracle --config configs/demo.yaml --condition observed
```

- [ ] **Step 4: Run full verification**

Run latest matrices:

```text
uv run --no-cache --isolated --no-project --no-python-downloads --python 3.10 --with-editable . --with pytest pytest -q -p no:cacheprovider
uv run --no-cache --isolated --no-project --no-python-downloads --python 3.12 --with-editable . --with pytest pytest -q -p no:cacheprovider
uv run --no-cache --isolated --no-project --no-python-downloads --python 3.12 --with pydantic==2.5.3 --with-editable . --with pytest pytest -q -p no:cacheprovider
```

Run exact analyzer integration:

```text
uv run --no-cache --isolated --no-project --no-python-downloads --python 3.12 \
  --with-editable '.[oracle]' --with pytest pytest -q -m oracle_tools
```

Expected: all unit/full matrices pass; the exact-tool corpus passes without network lookup.

- [ ] **Step 5: Commit**

```bash
git add pyproject.toml README.md tests src/secaware/oracle
git commit -m "test: gate exact static analyzers"
```

## Completion evidence

- `rg "use_lightweight_rules|findings_from_tsg|lightweight_rules" src configs tests` has no production-path matches.
- Missing Semgrep or Bandit produces the dedicated nonzero error and no Oracle manifest.
- Altering a policy byte or reported tool version produces `POLICY_MISMATCH`.
- Semgrep and Bandit malformed/partial reports produce `ANALYZER_INVALID_OUTPUT`.
- A full exact-tool corpus run proves both analyzers execute and no fallback participates.
- Oracle outputs and manifests pass strict readback, output-hash, policy-hash, lease, and producer-commit verification.
