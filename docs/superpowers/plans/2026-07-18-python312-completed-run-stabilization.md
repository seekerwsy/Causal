# Python 3.12 and Completed-Run Stabilization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix SecAware to the Python 3.12 minor line and make the `run-all` completed-run shortcut perform the same non-mutating semantic and transaction validation as the report stage.

**Architecture:** Package metadata is the only runtime-version authority and declares `>=3.12,<3.13`; source and tests use Python 3.12 standard-library APIs without 3.10 shims. Reporting exposes a validate-only entry point backed by the existing report transaction/semantic pipeline: valid committed reports are read and validated, invalid state fails closed without rebuilding, and pending report transactions are resolved under the normal stage lease before success is returned.

**Tech Stack:** Python 3.12, Pydantic 2, Typer, RunStore leases/manifests, report artifact transactions, pytest, Ruff, uv.

---

## File map

- `pyproject.toml`: authoritative Python minor-line and dependency declarations.
- `src/secaware/schema/{causal,experiments,outcomes}.py`: use standard-library `typing.Self`.
- `src/secaware/intervention/{attestation,graph_patch,executors}.py`: use standard-library `typing.Self`.
- `tests/test_{m6_architecture,m4b_architecture,packaging}.py`: enforce Python 3.12 metadata/imports and wheel metadata.
- `README.md`, `docs/migrations/prompt-only-fci-jci.md`: user-facing Python baseline.
- `docs/superpowers/plans/2026-07-13-secaware-prompt-only-fci-rollout.md`: superseding final matrix.
- `docs/superpowers/plans/2026-07-13-m6-itt-jci-rfci-reporting.md`: superseding M6 version matrix.
- `src/secaware/pipeline/stages/reporting.py`: validate-only committed-report path sharing all semantic and recovery logic.
- `src/secaware/cli.py`: terminal `run-all` delegates to committed-report validation instead of hash-only verification.
- `tests/test_run_all_demo.py`: end-to-end coordinated report/manifest tamper regression.
- `tests/test_prompt_only_reports.py`: validate-only transaction and no-rebuild regressions.

### Task 1: Enforce the Python 3.12 minor line

**Files:**
- Modify: `pyproject.toml`
- Modify: `src/secaware/schema/causal.py`
- Modify: `src/secaware/schema/experiments.py`
- Modify: `src/secaware/schema/outcomes.py`
- Modify: `src/secaware/intervention/attestation.py`
- Modify: `src/secaware/intervention/graph_patch.py`
- Modify: `src/secaware/intervention/executors.py`
- Modify: `tests/test_m6_architecture.py`
- Modify: `tests/test_m4b_architecture.py`
- Modify: `tests/test_packaging.py`
- Modify: `README.md`
- Modify: `docs/migrations/prompt-only-fci-jci.md`
- Modify: `docs/superpowers/plans/2026-07-13-secaware-prompt-only-fci-rollout.md`
- Modify: `docs/superpowers/plans/2026-07-13-m6-itt-jci-rfci-reporting.md`

- [ ] **Step 1: Replace the 3.10 compatibility gates with a failing 3.12-only gate**

In `tests/test_m6_architecture.py`, replace the two `test_python310_*` tests with one metadata/source test:

```python
def test_python_runtime_is_fixed_to_the_312_minor_line() -> None:
    metadata = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert metadata["project"]["requires-python"] == ">=3.12,<3.13"
    assert "typing-extensions" not in "\n".join(metadata["project"]["dependencies"]).casefold()
    assert "tomli" not in "\n".join(
        metadata["project"]["optional-dependencies"]["dev"]
    ).casefold()

    for relative in _PYTHON312_SELF_MODULES:
        tree = ast.parse((SOURCE_ROOT / relative).read_text(encoding="utf-8"))
        assert any(
            isinstance(node, ast.ImportFrom)
            and node.module == "typing"
            and any(alias.name == "Self" for alias in node.names)
            for node in ast.walk(tree)
        )
        assert not any(
            isinstance(node, ast.ImportFrom) and node.module == "typing_extensions"
            for node in ast.walk(tree)
        )

    for name in _TOMLLIB_TEST_MODULES:
        source = (PROJECT_ROOT / "tests" / name).read_text(encoding="utf-8")
        assert "import tomllib" in source
        assert "import tomli" not in source
```

In `tests/test_packaging.py`, add the package and wheel contract assertions:

```python
def test_project_declares_python312_as_the_only_supported_minor_line() -> None:
    project = tomllib.loads((PROJECT_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert project["project"]["requires-python"] == ">=3.12,<3.13"
```

Extend the existing wheel test to locate its single `*.dist-info/METADATA` member and assert:

```python
metadata_text = archive.read(metadata_members[0]).decode("utf-8")
assert "Requires-Python: >=3.12,<3.13\n" in metadata_text.replace("\r\n", "\n")
```

- [ ] **Step 2: Run the new gates and verify RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_m6_architecture.py::test_python_runtime_is_fixed_to_the_312_minor_line tests/test_packaging.py::test_project_declares_python312_as_the_only_supported_minor_line
```

Expected: FAIL because the current metadata is `>=3.10` and the temporary 3.10 compatibility dependencies/imports remain.

- [ ] **Step 3: Apply the minimal runtime and import changes**

Set:

```toml
requires-python = ">=3.12,<3.13"
```

Remove the direct `typing-extensions` dependency and the conditional `tomli` development dependency. In all six production modules, merge `Self` back into each existing standard-library `typing` import and remove `from typing_extensions import Self`. In the three tests, use one unconditional standard-library import:

```python
import tomllib
```

Do not alter the optional Oracle or RFCI pins.

- [ ] **Step 4: Update only authoritative current documentation**

Add a concise Python 3.12 requirement to `README.md` and `docs/migrations/prompt-only-fci-jci.md`. Change the master rollout and M6 plan tech-stack/final-matrix text so that only this command remains for the version matrix:

```powershell
uv run --no-project --python 3.12 --with-editable ".[dev,api]" pytest -q
```

Retain the separate Python 3.12 Oracle and RFCI capability commands. Do not rewrite historical M2–M5 plan commands; the approved 2026-07-18 runtime design explicitly supersedes them.

- [ ] **Step 5: Verify GREEN and adjacent packaging/import behavior**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_m6_architecture.py tests/test_m4b_architecture.py tests/test_packaging.py
.\.venv\Scripts\python.exe -c "import secaware; import secaware.cli; print('ok')"
.\.venv\Scripts\ruff.exe check pyproject.toml src/secaware/schema src/secaware/intervention tests/test_m6_architecture.py tests/test_m4b_architecture.py tests/test_packaging.py
```

Expected: all tests pass, the smoke command prints `ok`, and Ruff exits zero.

### Task 2: Validate completed reports without rebuilding

**Files:**
- Modify: `src/secaware/pipeline/stages/reporting.py`
- Modify: `src/secaware/cli.py`
- Modify: `tests/test_prompt_only_reports.py`
- Modify: `tests/test_run_all_demo.py`

- [ ] **Step 1: Add failing validate-only and completed-run tamper tests**

In `tests/test_prompt_only_reports.py`, add a committed-state test that imports `validate_committed_reports`, monkeypatches `_build_documents` to fail if called, and proves the validator returns the committed counts without rebuilding:

```python
def test_validate_committed_reports_never_rebuilds(published_reports, monkeypatch) -> None:
    module, store, result, _before, _after = published_reports
    monkeypatch.setattr(
        module,
        "_build_documents",
        lambda _snapshot: pytest.fail("validate-only path rebuilt reports"),
    )
    assert module.validate_committed_reports(store.config, store) == result
```

Add a pending-journal test using the real committed fixture:

```python
def test_validate_committed_reports_rejects_invalid_pending_transaction(published_reports) -> None:
    module, store, _result, _before, _after = published_reports
    journal = store.path(".stages", ".report.transaction.json")
    journal.write_text("{}\n", encoding="utf-8", newline="\n")
    with pytest.raises(SecAwareError, match="transaction recovery failed"):
        module.validate_committed_reports(store.config, store)
```

In the existing completed-run section of `tests/test_run_all_demo.py`, add a coordinated mutation that changes `reports/summary.md` and updates only the report manifest's matching `output_sha256`. Invoke `run-all` with and without `--force`; both must fail and `_run_tree_bytes(run_dir)` must remain byte-identical to the coordinated-tamper snapshot. Restore both original bytes in `finally`.

- [ ] **Step 2: Run the new tests and verify RED**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_prompt_only_reports.py::test_validate_committed_reports_never_rebuilds tests/test_prompt_only_reports.py::test_validate_committed_reports_rejects_invalid_pending_transaction
```

Expected: FAIL because `validate_committed_reports` does not exist.

Run the completed-run E2E node after adding its coordinated mutation. Expected: FAIL because the current shortcut accepts the report+manifest hash update.

- [ ] **Step 3: Add validate-only execution to the existing report pipeline**

Keep the current `write_reports` body and transaction callbacks. Extend only its signature and its
call to `_execute_report_transaction`:

```diff
 def write_reports(
     config: AppConfig,
     store: RunStore,
     force: bool = False,
+    *,
+    _validate_only: bool = False,
 ) -> ReportingStageResult:
```

```diff
             skipped = _execute_report_transaction(
                 store,
                 inputs=input_paths,
                 outputs=outputs,
                 force=force,
+                validate_only=_validate_only,
                 capture_input_snapshot=capture,
                 verify_input_snapshot=verify,
                 validate_committed=validate_committed,
                 build=build,
             )
```

Add the public validator after `write_reports`:

```python
def validate_committed_reports(
    config: AppConfig,
    store: RunStore,
) -> ReportingStageResult:
    return write_reports(config, store, force=False, _validate_only=True)
```

Add `validate_only: bool` to `_execute_report_transaction` and reject non-boolean values. Move all
committed-output readback and semantic validation into the `before_skip` callback so it executes
while `RunStore.should_skip_stage` still owns the report-stage lease. The outer `write_reports`
dependency context continues to hold every producer lease:

```python
def validate_skip() -> None:
    verify_input_snapshot()
    for spec in outputs:
        data = spec.path.read_bytes()
        _validate_output_bytes(spec, data)
    validate_committed()
    verify_input_snapshot()
```

Pass `before_skip=validate_skip`, not `before_skip=verify_input_snapshot`. The successful-skip block
then returns immediately because validation already completed under the lease:

```python
if store.should_skip_stage(
    _STAGE,
    inputs,
    output_paths,
    force,
    preserve_committed=True,
    after_lease_acquired=recover_or_cleanup,
    input_snapshot=capture_once,
    before_skip=validate_skip,
):
    return True
```

Immediately after that block, fail closed before creating `ArtifactTransaction` when validation-only
did not match a committed report:

```python
if validate_only:
    store.abort_stage(_STAGE)
    raise _error("committed report validation failed")
```

The validate-only path must never call `_build_documents`, write candidates, reseal outputs, record a
manifest, or change a valid/invalid run tree except for the existing deterministic
pending-transaction recovery contract.

- [ ] **Step 4: Route only the terminal shortcut through the validator**

Import `validate_committed_reports` in `src/secaware/cli.py`. Replace the hash-only call in the terminal-path branch:

```python
validate_committed_reports(cfg, store)
if force:
    raise SecAwareError(
        code=ErrorCode.MANIFEST_CONFLICT,
        stage="run-all",
        message="completed run is immutable; start a new run directory",
    )
```

Keep the normal final stage call as `write_reports(cfg, store, force=force)`. This preserves the testable distinction between a stage that may build reports and a completed-run validator that may not.

- [ ] **Step 5: Run GREEN and adjacent transaction regressions**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_prompt_only_reports.py tests/test_stage_orchestration.py tests/test_run_all_demo.py
```

Expected: PASS. The completed-run rerun makes no provider or build-stage call, coordinated tamper fails closed, invalid journal fails closed, and report rollback/skip tests remain green.

### Task 3: Reviews and one final milestone matrix

**Files:**
- Review: all Task 8 uncommitted files relative to `d85f2fd`

- [ ] **Step 1: Repeat spec review, then code-quality review**

The spec reviewer must confirm the approved Python 3.12 design, exact 14-command CLI, report validate-only semantics, and no Java requirement in the base import. Only after `SPEC COMPLIANT` may the quality reviewer check security, concurrency, atomicity, maintainability, and test quality. Fix every Critical/Important item through a new RED→GREEN cycle; record Minor debt without delaying the milestone.

- [ ] **Step 2: Run the focused M6 gate once**

Run the exact focused command from Task 8 of `2026-07-13-m6-itt-jci-rfci-reporting.md`, plus `tests/test_run_all_demo.py`, `tests/test_packaging.py`, and `tests/test_preflight.py`.

Expected: PASS; only explicitly capability-gated RFCI tests may skip.

- [ ] **Step 3: Run the single supported Python matrix and real-tool gates**

Run:

```powershell
uv run --no-project --python 3.12 --with-editable ".[dev,api]" pytest -q
uv run --no-cache --isolated --no-project --no-python-downloads --python 3.12 --with-editable ".[oracle]" --with pytest pytest -q -m oracle_tools
uv run --no-project --python 3.12 --with-editable ".[dev,api,rfci]" pytest -q -m rfci_real
```

Expected: the Python 3.12 full matrix and exact Oracle corpus pass. Run the RFCI command only when the pinned Python/JPype/py-tetrad runtime and a compatible JDK are available; otherwise preserve the explicit unavailable-capability evidence and do not change minimum results.

- [ ] **Step 4: Run final local verification once**

Run:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\ruff.exe check src tests
.\.venv\Scripts\ruff.exe format --check src tests
.\.venv\Scripts\python.exe -m compileall -q src tests
.\.venv\Scripts\python.exe -m secaware --help
.\.venv\Scripts\python.exe -m secaware confirm --help
.\.venv\Scripts\python.exe -m secaware analyze-jci --help
.\.venv\Scripts\python.exe -m secaware analyze-rfci --help
git diff --check
if (Test-Path uv.lock) { throw 'uv.lock must not exist' }
```

Expected: every command exits zero; only explicit capability-gated tests skip.

- [ ] **Step 5: Audit and commit the completed Task 8 diff**

Audit every frozen requirement against current files and fresh command evidence. Confirm no old modules/tests/facades or Code TSG/mechanism artifacts remain, the artifact inventory is exact, and the working tree contains no generated lock/build artifact. Stage only the intended Task 8 implementation, tests, plans, and migration files, then commit:

```powershell
git commit -m "docs: complete prompt-only fci jci rollout"
```
