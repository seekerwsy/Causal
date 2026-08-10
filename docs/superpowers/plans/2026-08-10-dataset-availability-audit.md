# Dataset Availability Audit Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a deterministic, fail-closed, fully provenance-preserving Stage 0 pipeline that migrates the approved benchmark snapshots, acquires pinned CyberSecEval v2 data, audits task/CWE/neutrality/functional-contract availability, simulates cluster-disjoint splits, and emits an immutable gap report without invoking an LLM or creating missing contracts.

**Architecture:** Add a focused `secaware.dataset_audit` package whose pure functions parse and classify records, while a coordinator owns immutable run creation, staged output, logging, and transactional publication. Reuse the current repository's strict JSONL and transaction primitives; adapt only compatible parsing and fingerprint ideas from the legacy repository, recording every reuse decision. Keep source snapshots and audit runs separate so repeated audits never overwrite either source evidence or historical results.

**Tech Stack:** Python 3.12, Pydantic v2, Typer, standard-library `hashlib/json/pathlib/urllib`, pytest, existing `secaware.io` transactional and canonical JSONL utilities.

---

## Frozen constraints

- No LLM, API model, GPU, or remote execution.
- No TSG extraction, causal discovery, intervention, generation, or Oracle execution.
- Neutrality is a deterministic pre-screen only; uncertain cases remain `UNRESOLVED`.
- Existing functional contracts may be inventoried or smoke-validated; missing contracts are not authored.
- Every source, command, configuration, environment record, intermediate artifact, failure, and result is retained under a new run ID.
- `paper/tmp/` and the unrelated root `uv.lock` remain untouched.
- Start with fixtures and 3--5 records per compatible dataset, then expand only after each gate passes.

## File structure

Create the following focused modules:

- `src/secaware/dataset_audit/__init__.py` — stable public exports only.
- `src/secaware/dataset_audit/schema.py` — enums and strict Pydantic artifact records.
- `src/secaware/dataset_audit/catalog.py` — frozen 12-file legacy catalog and CyberSecEval v2 source descriptor.
- `src/secaware/dataset_audit/fingerprints.py` — byte hashes, prompt normalization, exact/normalized prompt digests.
- `src/secaware/dataset_audit/migration.py` — verified byte-for-byte snapshot migration and migration manifest.
- `src/secaware/dataset_audit/acquisition.py` — pinned upstream commit resolution and v2 retrieval.
- `src/secaware/dataset_audit/adapters.py` — dataset-specific prompt/ID/language/CWE/contract evidence extraction.
- `src/secaware/dataset_audit/neutrality.py` — closed, versioned deterministic neutrality pre-screen.
- `src/secaware/dataset_audit/clustering.py` — duplicate groups and conservative task clusters.
- `src/secaware/dataset_audit/functionality.py` — functional-evidence classification and safe smoke-validation dispatch.
- `src/secaware/dataset_audit/splits.py` — deterministic cluster-disjoint split simulations.
- `src/secaware/dataset_audit/roles.py` — dataset role assignment from audited evidence.
- `src/secaware/dataset_audit/run.py` — run coordinator, progress counters, failures, and report assembly.
- `src/secaware/dataset_audit/report.py` — canonical JSON and human-readable Markdown gap report.
- `src/secaware/commands/dataset_audit.py` — CLI-facing orchestration kept out of the main CLI module.
- `configs/dataset-audit/audit-v1.json` — checked-in reproducible default configuration.
- `tests/dataset_audit/fixtures/` — tiny synthetic source fixtures, never paper results.
- `tests/dataset_audit/*.py` — component and gated integration tests.
- `docs/dataset-audit/reuse-ledger.md` — explicit legacy reuse/rejection record.
- `docs/dataset-audit/runbook.md` — exact local execution and recovery procedure.

Modify:

- `src/secaware/cli.py` — register one `audit-datasets` command delegating to the focused command module.
- `.gitignore` — ignore immutable run payloads and downloaded snapshots while retaining manifests/configuration through explicit negation rules if needed.

Runtime-only paths created by the command:

```text
datasets/snapshots/legacy-2026-08-10/
datasets/sources/cyberseceval/<resolved-commit>/
datasets/manifests/audit-v1/
runs/dataset-audit/<run-id>/
```

### Task 1: Freeze schemas, catalog, and legacy reuse ledger

**Files:**
- Create: `src/secaware/dataset_audit/__init__.py`
- Create: `src/secaware/dataset_audit/schema.py`
- Create: `src/secaware/dataset_audit/catalog.py`
- Create: `tests/dataset_audit/test_schema_and_catalog.py`
- Create: `docs/dataset-audit/reuse-ledger.md`

- [ ] **Step 1: Write failing schema and catalog tests**

Define tests that require strict enums, reject unknown fields, and assert the exact 12-file catalog plus the v2 descriptor:

```python
from pydantic import ValidationError
import pytest

from secaware.dataset_audit.catalog import LEGACY_SOURCES, cyberseceval_v2_source
from secaware.dataset_audit.schema import NeutralityState, RecordAudit


def test_catalog_freezes_exact_legacy_inputs() -> None:
    assert [item.filename for item in LEGACY_SOURCES] == [
        "apps.jsonl", "classeval.jsonl", "cweval.jsonl", "cweval_python.jsonl",
        "cyberseceval_discover_adv.jsonl", "cyberseceval_secure_code.jsonl",
        "humaneval.jsonl", "humaneval_plus.jsonl", "mbpp.jsonl", "sallm.jsonl",
        "seccodebench_python.jsonl", "securityeval.jsonl",
    ]
    assert cyberseceval_v2_source().relative_path.endswith("instruct-v2.json")


def test_record_audit_is_strict() -> None:
    with pytest.raises(ValidationError):
        RecordAudit.model_validate({"schema_version": "1.0", "unexpected": True})
    assert NeutralityState.UNRESOLVED.value == "UNRESOLVED"
```

- [ ] **Step 2: Run the focused test and confirm it fails**

Run:

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_schema_and_catalog.py -q
```

Expected: collection fails because `secaware.dataset_audit` does not exist.

- [ ] **Step 3: Implement strict artifact schemas and source descriptors**

Include these exact enum values:

```python
class CweEvidence(str, Enum):
    EXPLICIT_FIELD = "EXPLICIT_FIELD"
    SOURCE_ID_PARSE = "SOURCE_ID_PARSE"
    SOURCE_MAPPING = "SOURCE_MAPPING"
    CONFLICTING = "CONFLICTING"
    UNRESOLVED = "UNRESOLVED"

class NeutralityState(str, Enum):
    OBVIOUS_CONFLICT = "OBVIOUS_CONFLICT"
    CANDIDATE_NEUTRAL = "CANDIDATE_NEUTRAL"
    UNRESOLVED = "UNRESOLVED"

class FunctionalState(str, Enum):
    EXECUTABLE_VALIDATED = "EXECUTABLE_VALIDATED"
    PRESENT_UNVALIDATED = "PRESENT_UNVALIDATED"
    REFERENCE_ONLY = "REFERENCE_ONLY"
    ABSENT = "ABSENT"
    CONFLICTING = "CONFLICTING"
    UNRESOLVED = "UNRESOLVED"
```

Use `ConfigDict(extra="forbid", frozen=True)` for all persisted records. Model source coordinates, evidence spans, hashes, duplicate/cluster identifiers, role assignments, failure records, and progress counts explicitly rather than storing an untyped catch-all dictionary.

- [ ] **Step 4: Record the reuse boundary**

In `docs/dataset-audit/reuse-ledger.md`, record:

```text
catalog.py: consult dataset identifiers and source-field knowledge; adapt to frozen audit catalog.
importer.py: consult prompt/ID resolution; do not reuse network/Hugging Face loading.
build.py: adapt prompt fingerprint and disjoint grouping ideas; replace row-level split with conservative cluster split.
triage.py: reject direct reuse because it invokes generation and security analysis outside Stage 0.
Current io/jsonl.py and io/transaction.py: reuse directly for strict parsing and transactional publication.
```

- [ ] **Step 5: Run tests and commit**

Run the focused test, then:

```powershell
git add src/secaware/dataset_audit tests/dataset_audit/test_schema_and_catalog.py docs/dataset-audit/reuse-ledger.md
git commit -m "feat: define dataset audit contracts"
```

Expected: focused test passes; commit contains schemas, catalog, and ledger only.

### Task 2: Implement deterministic fingerprints and strict source adapters

**Files:**
- Create: `src/secaware/dataset_audit/fingerprints.py`
- Create: `src/secaware/dataset_audit/adapters.py`
- Create: `tests/dataset_audit/test_fingerprints.py`
- Create: `tests/dataset_audit/test_adapters.py`
- Create: `tests/dataset_audit/fixtures/adapter_records.jsonl`

- [ ] **Step 1: Write failing fingerprint tests**

Require byte SHA-256, exact prompt SHA-256, and a conservative normalized digest that changes neither semantic tokens nor punctuation ordering:

```python
def test_normalized_prompt_digest_collapses_only_layout() -> None:
    assert normalized_prompt_sha256("Build  an API\r\nnow") == normalized_prompt_sha256(
        "Build an API\nnow"
    )
    assert normalized_prompt_sha256("Build safe API") != normalized_prompt_sha256(
        "Build unsafe API"
    )
```

- [ ] **Step 2: Write failing adapter tests**

Use fixture records for explicit CWE, ID-derived CWE, conflicting CWE fields, missing prompt, language evidence, and functional-test references. Assert missing or contradictory evidence becomes `UNRESOLVED`/`CONFLICTING`, never guessed.

- [ ] **Step 3: Verify both test files fail**

Run:

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_fingerprints.py tests/dataset_audit/test_adapters.py -q
```

Expected: imports fail for the two new modules.

- [ ] **Step 4: Implement pure fingerprint functions**

Expose:

```python
def file_sha256(path: Path) -> str: ...
def exact_prompt_sha256(prompt: str) -> str: ...
def normalize_prompt(prompt: str) -> str: ...
def normalized_prompt_sha256(prompt: str) -> str: ...
```

Normalization is versioned as `prompt-normalization-v1`, applies Unicode NFC, newline normalization, trailing-space removal, and whitespace-run collapse. It must not lowercase text, strip punctuation, reorder tokens, or redact security terms.

- [ ] **Step 5: Implement source adapters**

Expose `adapt_record(source_id, source_path, line_number, raw) -> AdaptedRecord`. Resolve prompt and ID using a closed field map per catalog entry. Preserve every evidence source and raw source coordinate. Parse only syntactically explicit CWE identifiers matching `CWE-[0-9]+`; if multiple non-equivalent identifiers remain, emit `CONFLICTING`.

- [ ] **Step 6: Run tests and commit**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_fingerprints.py tests/dataset_audit/test_adapters.py -q
git add src/secaware/dataset_audit tests/dataset_audit
git commit -m "feat: add deterministic dataset adapters"
```

Expected: all adapter and fingerprint tests pass.

### Task 3: Add verified, non-overwriting legacy migration

**Files:**
- Create: `src/secaware/dataset_audit/migration.py`
- Create: `tests/dataset_audit/test_migration.py`
- Modify: `.gitignore`

- [ ] **Step 1: Write failing migration tests**

Test a two-file temporary source catalog and require:

```python
def test_migration_is_byte_exact_and_refuses_overwrite(tmp_path: Path) -> None:
    result = migrate_legacy_sources(source_root, destination_root, catalog)
    assert result.files[0].source_sha256 == result.files[0].destination_sha256
    assert (destination_root / "a.jsonl").read_bytes() == (source_root / "a.jsonl").read_bytes()
    with pytest.raises(MigrationConflictError):
        migrate_legacy_sources(source_root, destination_root, catalog)
```

Also test missing files, symlinks, digest mismatch after copy, and partial-copy cleanup. Existing matching immutable snapshots may be verified and reported as `ALREADY_VERIFIED`; differing targets must fail closed.

- [ ] **Step 2: Verify the migration tests fail**

Run the single test module and expect a missing-module failure.

- [ ] **Step 3: Implement staged copy and manifest generation**

Copy each regular file into a run-local staging directory, flush it, hash source and staged copy, then publish the complete snapshot directory only after all 12 hashes match. Persist `migration-manifest.json` with source/destination absolute paths, sizes, timestamps, digests, migration time, and status. Never alter the source tree.

- [ ] **Step 4: Add runtime ignore rules**

Ignore downloaded source payloads and run payloads, while keeping checked-in configs, runbook, and tests visible. Confirm with `git status --short` that unrelated `paper/tmp/` and `uv.lock` remain unchanged.

- [ ] **Step 5: Run focused and adjacent transaction tests**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_migration.py tests/test_jsonl_stage_transaction.py tests/test_artifact_store.py -q
```

Expected: migration and existing transaction regression tests pass.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/dataset_audit/migration.py tests/dataset_audit/test_migration.py .gitignore
git commit -m "feat: add immutable dataset snapshot migration"
```

### Task 4: Add pinned CyberSecEval v2 acquisition with offline failure evidence

**Files:**
- Create: `src/secaware/dataset_audit/acquisition.py`
- Create: `tests/dataset_audit/test_acquisition.py`

- [ ] **Step 1: Write failing acquisition tests with a local fake transport**

Inject a transport interface so unit tests never use the network:

```python
class SourceTransport(Protocol):
    def resolve_commit(self, repository: str, revision: str) -> str: ...
    def fetch_bytes(self, repository: str, commit: str, path: str) -> bytes: ...
```

Test that a symbolic revision resolves to a 40-character commit, the output path includes that commit, `source-lock.json` records URL/path/time/size/SHA-256, a second differing payload cannot overwrite the pinned file, and transport failure yields a structured `UPSTREAM_UNAVAILABLE` failure.

- [ ] **Step 2: Verify the acquisition tests fail**

Run the module and expect import failure.

- [ ] **Step 3: Implement GitHub-compatible resolution and retrieval**

Use standard-library HTTPS with explicit timeouts, bounded response sizes, and dependency injection. Accept only HTTPS official-source URLs from the frozen catalog. Download to staging, verify expected file shape as JSON, hash, and publish under the resolved commit. Do not silently substitute cached or legacy data when upstream retrieval fails.

- [ ] **Step 4: Run tests and commit**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_acquisition.py -q
git add src/secaware/dataset_audit/acquisition.py tests/dataset_audit/test_acquisition.py
git commit -m "feat: acquire pinned CyberSecEval v2 source"
```

### Task 5: Implement neutrality, duplication, and conservative task clustering

**Files:**
- Create: `src/secaware/dataset_audit/neutrality.py`
- Create: `src/secaware/dataset_audit/clustering.py`
- Create: `tests/dataset_audit/test_neutrality.py`
- Create: `tests/dataset_audit/test_clustering.py`

- [ ] **Step 1: Write failing neutrality tests**

Freeze `neutrality-prescreen-v1` as a closed set of high-precision conflict patterns for prompts that explicitly ask to exploit, inject, bypass, weaken, remove, or repair a named security flaw. Require matched spans and pattern IDs. Require ambiguous security vocabulary without an explicit instruction to be `UNRESOLVED`; ordinary functional prompts without matched conflict evidence may be `CANDIDATE_NEUTRAL`.

- [ ] **Step 2: Write failing clustering tests**

Test exact duplicate groups, normalized duplicate groups, explicit shared task IDs, repository/file coordinates, transitive union, and ambiguous cross-source similarity. Only deterministic strong evidence may union clusters. Ambiguous similarity emits an unresolved relation and prevents the affected records from being counted as independent without automatically merging unrelated tasks.

- [ ] **Step 3: Verify tests fail**

Run both focused modules and expect missing imports.

- [ ] **Step 4: Implement closed neutrality pre-screen**

Define rules as an immutable tuple in code with stable IDs and explanations. Return state, rule version, matched spans, and rationale. Do not expose a runtime registry or user-supplied regex extension point.

- [ ] **Step 5: Implement union-find clustering with evidence records**

Cluster priority is exact source task identity, repository/file coordinate, exact prompt digest, then normalized prompt digest. Emit stable cluster IDs derived from sorted member coordinates. Store every edge/evidence type used to form a cluster.

- [ ] **Step 6: Run tests and commit**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_neutrality.py tests/dataset_audit/test_clustering.py -q
git add src/secaware/dataset_audit/neutrality.py src/secaware/dataset_audit/clustering.py tests/dataset_audit
git commit -m "feat: classify neutrality and task clusters"
```

### Task 6: Inventory and safely validate existing functional contracts

**Files:**
- Create: `src/secaware/dataset_audit/functionality.py`
- Create: `tests/dataset_audit/test_functionality.py`
- Create: `tests/dataset_audit/fixtures/functional_contracts/`

- [ ] **Step 1: Write failing classification tests**

Cover all six states. A record with inline tests or a resolvable local test reference is `PRESENT_UNVALIDATED`; a prose reference is `REFERENCE_ONLY`; contradictory fields are `CONFLICTING`; missing evidence is `ABSENT`; unrecognized evidence is `UNRESOLVED`.

- [ ] **Step 2: Write failing smoke-validation tests**

Use only controlled fixtures. Require an explicit allowlisted harness adapter and bounded execution through the existing process-isolation path. Successful fixture execution becomes `EXECUTABLE_VALIDATED`; timeout, crash, missing dependency, or unsupported harness remains a diagnostic failure and never becomes a generated-code outcome.

- [ ] **Step 3: Verify the tests fail**

Run the module and expect missing imports.

- [ ] **Step 4: Implement inventory first, validation second**

Expose:

```python
def classify_functional_evidence(record: AdaptedRecord, dataset_root: Path) -> FunctionalAssessment: ...
def smoke_validate_existing_contract(assessment: FunctionalAssessment, limits: SmokeLimits) -> FunctionalAssessment: ...
```

The dispatcher must reject unknown harnesses. It must not synthesize tests, reference implementations, counterpart prompts, or attestations.

- [ ] **Step 5: Run focused and isolation regressions**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_functionality.py tests/test_functional_outcome_contract.py tests/test_bounded_traversal_security.py -q
```

Expected: all pass without Semgrep, Bandit, Java, API credentials, or network.

- [ ] **Step 6: Commit**

```powershell
git add src/secaware/dataset_audit/functionality.py tests/dataset_audit
git commit -m "feat: audit existing functional contracts"
```

### Task 7: Simulate cluster-disjoint splits and assign evidence-based dataset roles

**Files:**
- Create: `src/secaware/dataset_audit/splits.py`
- Create: `src/secaware/dataset_audit/roles.py`
- Create: `tests/dataset_audit/test_splits.py`
- Create: `tests/dataset_audit/test_roles.py`

- [ ] **Step 1: Write failing split tests**

For ratios `0.5`, `0.6`, and `0.7`, require deterministic assignment by conservative task cluster, no cluster crossing discover/confirm, and counts by source/language/CWE/neutrality/functional state. Require unresolved clusters to be excluded from independent-task counts and reported separately. Assert that the count of 20 is labeled `pipeline_floor_met`, not `adequately_powered`.

- [ ] **Step 2: Write failing role tests**

Require the exact role vocabulary from the design. Examples:

```python
assert assign_roles(dataset_with_neutral_secure_functional_tasks) == {
    DatasetRole.PAPER_PRIMARY_CANDIDATE
}
assert DatasetRole.PENDING_CONTRACT_OR_ADJUDICATION in assign_roles(
    dataset_without_executable_contracts
)
```

Do not assign `discovery-only` merely because functional contracts are missing.

- [ ] **Step 3: Verify tests fail**

Run both modules and expect missing imports.

- [ ] **Step 4: Implement deterministic split simulation**

Use `random.Random(seed)` only on a sorted list of cluster IDs, stratify conservatively by primary CWE and source, and persist seed plus algorithm version `cluster-split-v1`. Return assignments and summary tables; do not write files in this pure module.

- [ ] **Step 5: Implement role decision table**

Make role assignment a transparent ordered decision table over observed evidence. Preserve multiple compatible roles where justified. Every assignment includes machine-readable supporting and blocking reasons.

- [ ] **Step 6: Run tests and commit**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_splits.py tests/dataset_audit/test_roles.py -q
git add src/secaware/dataset_audit/splits.py src/secaware/dataset_audit/roles.py tests/dataset_audit
git commit -m "feat: simulate dataset splits and roles"
```

### Task 8: Build immutable run coordination, reports, and failure recovery

**Files:**
- Create: `src/secaware/dataset_audit/run.py`
- Create: `src/secaware/dataset_audit/report.py`
- Create: `tests/dataset_audit/test_run.py`
- Create: `tests/dataset_audit/test_report.py`

- [ ] **Step 1: Write failing immutable-run tests**

Require run IDs of the form `<UTC timestamp>-<config digest prefix>`, refusal to reuse an existing run directory, staged creation, and transactional final publication. Simulate an exception after three artifacts and assert `failures.jsonl` plus a failed-run manifest survive, no prior run changes, and a rerun receives a new ID with `supersedes_run_id`.

- [ ] **Step 2: Write failing report tests**

Require all artifact names from the design and a report containing:

```text
total, completed, running, failed, unresolved, pending, records_per_second, eta_seconds
counts by dataset, language, CWE, neutrality, functional state, cluster, split ratio, and role
CyberSecEval 150/260/v2 overlap relation
gaps blocking final CWE and sample-size freeze
```

Canonical JSON output must be byte-identical for two runs with identical inputs after excluding declared runtime-only timestamps and run IDs from the comparison digest.

- [ ] **Step 3: Verify tests fail**

Run both modules and expect missing imports.

- [ ] **Step 4: Implement coordinator phases**

The coordinator executes and logs these phases in order: preflight, migration verification, optional v2 acquisition, strict parsing, adaptation, neutrality, functionality inventory/smoke sample, clustering, overlap analysis, split simulation, role assignment, report assembly, transactional publication. Each phase updates progress and catches record-level failures without concealing dataset-level fatal errors.

- [ ] **Step 5: Implement complete artifacts and Markdown gap report**

Write canonical JSONL in stable source/line order. Include `commands.jsonl`, `environment.json`, and structured `run.log.jsonl`; redact secret-valued environment variables by recording presence and digest only. The Markdown report must distinguish verified fact, deterministic pre-screen, unresolved evidence, and later-study recommendation.

- [ ] **Step 6: Run focused and transaction regressions**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_run.py tests/dataset_audit/test_report.py tests/test_jsonl_stage_transaction.py tests/test_artifact_store.py -q
```

- [ ] **Step 7: Commit**

```powershell
git add src/secaware/dataset_audit/run.py src/secaware/dataset_audit/report.py tests/dataset_audit
git commit -m "feat: add reproducible dataset audit runs"
```

### Task 9: Register the CLI and checked-in reproducible configuration

**Files:**
- Create: `src/secaware/commands/dataset_audit.py`
- Create: `configs/dataset-audit/audit-v1.json`
- Create: `tests/dataset_audit/test_cli.py`
- Modify: `src/secaware/cli.py`

- [ ] **Step 1: Write failing CLI tests**

Use Typer's test runner. Require `audit-datasets --help`, explicit source/workspace/output/config paths, `--sample-only`, `--skip-v2-download`, and `--supersedes-run-id`. Confirm the command rejects output outside the repository, a missing 12-file source set, an existing run ID, and configurations containing API/model/server fields.

- [ ] **Step 2: Verify the CLI test fails**

Run the focused module and expect the command to be absent.

- [ ] **Step 3: Implement command delegation and frozen config**

The default config must contain:

```json
{
  "schema_version": "1.0",
  "audit_version": "audit-v1",
  "legacy_snapshot_id": "legacy-2026-08-10",
  "neutrality_rule_version": "neutrality-prescreen-v1",
  "prompt_normalization_version": "prompt-normalization-v1",
  "cluster_version": "task-cluster-v1",
  "split_version": "cluster-split-v1",
  "split_ratios": [0.5, 0.6, 0.7],
  "seed": 20260810,
  "smoke_records_per_dataset": 5,
  "minimum_cluster_floor": 20
}
```

The command module translates validated CLI input into `AuditRequest`; the main CLI only registers and forwards it.

- [ ] **Step 4: Run CLI and packaging regressions**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit/test_cli.py tests/test_packaging.py -q
```

- [ ] **Step 5: Commit**

```powershell
git add src/secaware/commands/dataset_audit.py src/secaware/cli.py configs/dataset-audit/audit-v1.json tests/dataset_audit/test_cli.py
git commit -m "feat: expose dataset availability audit CLI"
```

### Task 10: Execute the gated local audit without v2 network acquisition

**Files:**
- Runtime create: `datasets/snapshots/legacy-2026-08-10/`
- Runtime create: `datasets/manifests/audit-v1/migration-manifest.json`
- Runtime create: `runs/dataset-audit/<sample-run-id>/`
- Runtime create: `runs/dataset-audit/<legacy-full-run-id>/`

- [ ] **Step 1: Record the local environment before execution**

Confirm and persist machine identifier, OS, Python 3.12 executable/version, repository commit, branch, dirty paths, working directory `D:\MyCode\Causal`, source root `D:\MyCode\SecAware-Causal\datasets\benchmarks`, and all output roots. Do not record the user's server password or any API secret.

- [ ] **Step 2: Run fixture-level tests**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit -q
```

Expected: all component tests pass without network.

- [ ] **Step 3: Run 3--5 records per dataset in sample-only mode**

```powershell
.venv\Scripts\secaware.exe audit-datasets --config configs/dataset-audit/audit-v1.json --source-root D:\MyCode\SecAware-Causal\datasets\benchmarks --workspace-root D:\MyCode\Causal --sample-only --skip-v2-download
```

Expected: 12 datasets represented; no LLM/API/server activity; complete sample artifacts; failures and unresolved records explicitly counted.

- [ ] **Step 4: Inspect abnormal records before scale-up**

For every failure or unexpected count, trace the source coordinate, adapter decision, evidence, and log entry. Fix code or catalog errors with a new test and new commit; do not attribute anomalies to randomness. Rerun under a new run ID linked through `supersedes_run_id`.

- [ ] **Step 5: Run one small full dataset and the 150/260 overlap gate**

Select the smallest structurally representative dataset plus both existing CyberSecEval files. Confirm exact/normalized overlap counts, cluster independence, and stable re-execution digests before all-source scale-up.

- [ ] **Step 6: Run all 12 legacy datasets**

Execute the same command without `--sample-only`, still with `--skip-v2-download`. Report total/completed/running/failed/unresolved/pending, current records/second, and ETA while it runs. If any record fails, diagnose, repair, and backfill in a new complete run rather than silently dropping it.

- [ ] **Step 7: Verify deterministic rerun**

Run a second legacy-full audit with identical input/config and compare declared stable artifact digests. Expected: stable artifacts match; run IDs and timestamps differ only in declared provenance fields.

- [ ] **Step 8: Commit only code/config/docs, not runtime payloads**

Confirm `git status --short` does not stage datasets, runs, `paper/tmp/`, or `uv.lock`. Commit any execution-discovered code correction separately with its regression test.

### Task 11: Acquire v2, complete combined audit, and freeze the Stage 0 gap report

**Files:**
- Runtime create: `datasets/sources/cyberseceval/<resolved-commit>/instruct-v2.json`
- Runtime create: `datasets/manifests/audit-v1/source-lock.json`
- Runtime create: `runs/dataset-audit/<combined-run-id>/`
- Create: `docs/dataset-audit/runbook.md`

- [ ] **Step 1: Preflight network acquisition without increasing concurrency**

Check local network reachability and official upstream metadata using one request at a time. Record latency and failures. Do not use the remote model server or Alibaba Bailian.

- [ ] **Step 2: Run the v2-enabled audit**

```powershell
.venv\Scripts\secaware.exe audit-datasets --config configs/dataset-audit/audit-v1.json --source-root D:\MyCode\SecAware-Causal\datasets\benchmarks --workspace-root D:\MyCode\Causal
```

Expected: upstream revision resolves to an immutable commit; bytes and source lock are preserved; combined report includes legacy/v2 relationship. If acquisition fails, the run finishes as explicitly incomplete with `UPSTREAM_UNAVAILABLE`; it must not claim Stage 0 completion.

- [ ] **Step 3: Inspect and resolve all implementation failures**

Differentiate malformed source records, missing metadata, unsupported functional harnesses, unresolved adjudication, and implementation defects. Only implementation defects are repaired here. Preserve all earlier failed runs and create a linked rerun for corrections.

- [ ] **Step 4: Write the runbook from verified commands**

Document prerequisites, exact local paths, sample/full/v2 commands, artifact meanings, immutable rerun policy, failure recovery, progress interpretation, and how to compare stable digests. Include the rule that primary-paper eligibility is not final until later human adjudication and power analysis.

- [ ] **Step 5: Run the final targeted verification**

```powershell
.venv\Scripts\python.exe -m pytest tests/dataset_audit tests/test_jsonl_stage_transaction.py tests/test_artifact_store.py tests/test_packaging.py -q
```

Expected: all targeted and adjacent regression tests pass.

- [ ] **Step 6: Run one final full repository suite**

```powershell
.venv\Scripts\python.exe -m pytest -q
```

Expected: full suite passes. Real Semgrep/Bandit and RFCI integration are not rerun unless ordinary tests indicate an affected boundary, because this work does not modify Oracle or RFCI code.

- [ ] **Step 7: Visually and semantically review the report**

Confirm the Markdown report is readable and that each conclusion is supported by a nearby table. Verify it does not freeze CWE scope, sample size, model choice, RQ claims, or ITT conclusions. Confirm every unresolved category and dataset gap remains visible.

- [ ] **Step 8: Commit documentation and final implementation corrections**

```powershell
git add docs/dataset-audit/runbook.md
git commit -m "docs: add reproducible dataset audit runbook"
```

## Completion evidence

Before claiming Stage 0 complete, capture all of the following in the final progress report:

- Git commit and branch used for every run.
- Exact Python version, machine, working directory, source root, and output roots.
- Twelve legacy source hashes plus pinned v2 commit/path/hash.
- Total/completed/running/failed/unresolved/pending counts.
- Runtime rate and elapsed time for sample, legacy-full, deterministic rerun, and combined run.
- Exact and normalized duplicate groups and conservative independent task-cluster counts.
- Counts by dataset, language, CWE evidence, neutrality state, and functional state.
- 50/50, 60/40, and 70/30 cluster-disjoint split simulations.
- Evidence-based dataset roles and explicit blockers.
- CyberSecEval 150/260/v2 overlap characterization.
- Stable digest comparison between identical reruns.
- Focused, adjacent, and final full-suite test results.
- Confirmation that no LLM/API/server/GPU was used and no missing contract was authored.

