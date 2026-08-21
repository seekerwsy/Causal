# Dataset availability audit runbook

## Purpose and decision boundary

This runbook reproduces the Stage 0 inventory, provenance, duplicate/task-cluster,
split-feasibility, and evidence-based role audit. It does not generate code, run a
security Oracle, call an LLM, or estimate a causal/ITT effect.

The audit output is a pre-screen. It does not freeze the paper's CWE scope, sample
size, model choice, RQ claims, or ITT conclusions. `CANDIDATE_NEUTRAL` is not a human
attestation, the minimum cluster floor is not a power calculation, and a suggested
dataset role is not final primary-paper eligibility. Human adjudication, executable
functional-contract validation, and power analysis remain later gates.

## Verified execution environment

The completed 2026-08-10 run used:

| Item | Verified value |
|---|---|
| Machine | `DESKTOP-ES5QORS` |
| Platform | Windows 11 (`10.0.26200`) |
| Python | `3.12.13`, 64-bit CPython |
| Python executable | `D:\MyCode\Causal\.venv\Scripts\python.exe` |
| Branch | `codex/dataset-availability-audit` |
| Final audit commit | `a08e90d3947f293ffbb50ec989c6a686ad2d6062` |
| Worktree | `D:\MyCode\Causal\.worktrees\dataset-availability-audit` |
| Legacy source root | `D:\MyCode\SecAware-Causal\datasets\benchmarks` |
| Snapshot/output root | `D:\MyCode\Causal\.worktrees\dataset-availability-audit` |
| Final run directories | `runs\dataset-audit\stage0-combined-20260810-07` and `-08` |

The final audit did not use an LLM, model API, Alibaba Bailian, the remote model
server, a GPU, Semgrep/Bandit, or the RFCI backend. No missing functional contract
was authored to make a dataset appear eligible.

## Prerequisites and path discipline

1. Use the fixed project Python environment. Set `PYTHONPATH=src` because the
   verified commands execute the worktree source directly.
2. Keep the legacy source root read-only. Migration copies bytes into a verified
   snapshot and records source/destination hashes.
3. Keep every `run-id` unique. Never delete, rename, reuse, or overwrite a completed,
   failed, or staging run directory.
4. Use `--supersedes-run-id` for a corrected rerun. This expresses lineage without
   destroying history.
5. Use one network request/transport operation at a time for the first v2
   acquisition. Do not increase concurrency during source acquisition.
6. Store all runtime artifacts below the explicit `--workspace-root`; do not scatter
   downloads or results elsewhere.

Runtime data is intentionally Git-ignored:

- `datasets/snapshots/legacy-2026-08-10/`
- `datasets/sources/cyberseceval_instruct_v2/<commit>/`
- `datasets/manifests/audit-v1/source-lock.json`
- `runs/dataset-audit/<run-id>/`

The checked-in configuration is
`configs/dataset-audit/audit-v1.json`. The reuse decisions are in
`docs/dataset-audit/reuse-ledger.md`.

## Verified commands

Run all commands from
`D:\MyCode\Causal\.worktrees\dataset-availability-audit` in PowerShell.

### 1. Preflight

```powershell
$env:PYTHONPATH = 'src'
D:\MyCode\Causal\.venv\Scripts\python.exe --version
git status --short
```

Confirm the Python version, source root, workspace root, free disk space, and a clean
Git state before any full run. Do not start if an intended `run-id` already exists.

### 2. Small-case validation

This validates 5 records from each of the 12 legacy sources without network access:

```powershell
$env:PYTHONPATH = 'src'
D:\MyCode\Causal\.venv\Scripts\python.exe -m secaware audit-datasets `
  --config configs\dataset-audit\audit-v1.json `
  --source-root D:\MyCode\SecAware-Causal\datasets\benchmarks `
  --workspace-root D:\MyCode\Causal\.worktrees\dataset-availability-audit `
  --run-id stage0-sample-20260810-03 `
  --supersedes-run-id stage0-sample-20260810-02 `
  --sample-only `
  --skip-v2-download
```

Verified result: 60 completed, 0 failed, 32 unresolved, 0 pending; 156.85
records/second and 0.383 seconds of measured audit time.

### 3. Legacy-only full audit

Choose a new run identifier before reusing this command:

```powershell
$env:PYTHONPATH = 'src'
D:\MyCode\Causal\.venv\Scripts\python.exe -m secaware audit-datasets `
  --config configs\dataset-audit\audit-v1.json `
  --source-root D:\MyCode\SecAware-Causal\datasets\benchmarks `
  --workspace-root D:\MyCode\Causal\.worktrees\dataset-availability-audit `
  --run-id <new-legacy-run-id> `
  --skip-v2-download
```

The verified deterministic pair was `stage0-legacy-full-20260810-05` and `-06`:
1,367 completed, 0 failed, 663 unresolved, 0 pending. Rates were 56.13 and 60.00
records/second (24.354 and 22.782 seconds); both stable digests were
`c389498523826a756435ee13bc8f5357f1179dafbf3deb80f820d542df2eb49f`.

### 4. v2-enabled combined audit

The first execution may access the official PurpleLlama Git repository. It resolves
the requested revision to an immutable commit, downloads that exact file, hashes it,
and writes `source-lock.json`. Later runs treat the existing lock as authoritative and
reuse/refetch the locked commit rather than resolving a moving branch again.

```powershell
$env:PYTHONPATH = 'src'
D:\MyCode\Causal\.venv\Scripts\python.exe -m secaware audit-datasets `
  --config configs\dataset-audit\audit-v1.json `
  --source-root D:\MyCode\SecAware-Causal\datasets\benchmarks `
  --workspace-root D:\MyCode\Causal\.worktrees\dataset-availability-audit `
  --run-id <new-combined-run-id> `
  --supersedes-run-id <previous-related-run-id>
```

The final deterministic pair was `stage0-combined-20260810-07` and `-08`. Both used
the same clean commit, completed 3,048 records with 0 failures, 734 unresolved and 0
pending, and produced stable digest
`2d5c16c613988dffd7f9a9299bcb7a43ef8fab6cc91ad45ae0b8e99c11cc38a8`.
Rates were 47.03 and 46.75 records/second (64.810 and 65.199 seconds).

## Source locks and hashes

The 12 migrated files have identical source and snapshot hashes:

| Source | SHA-256 |
|---|---|
| `apps` | `f4bdcac23b3fdcd2bec5f6b8dc149d113adaef9d0990c0f05ce4ec89fdf4390e` |
| `classeval` | `b21e5bc4fdf0f3188e281525afadcdd531d4ab54bac06f188f9a827fb8156da6` |
| `cweval` | `36d20375a63da4846cb030e59893d01b8ea51b1adcaacba1625fcaf05278d3e3` |
| `cweval_python` | `e330f39d57716e7bf2127b9e536f1370bd563f54188d82c4bd41b7c1bbfa2d4c` |
| `cyberseceval_discover_adv` | `27f7997a3f6091597547527ef27c61799f52672fb37fcc7d5e329b639abd65ba` |
| `cyberseceval_secure_code` | `5ddb37958ffd78246a6f54d64cad70b35ea6051f1d465657b9509d402a851134` |
| `humaneval` | `fff0a5227679633d3047d48b2b0d9aeda4bc09d4ece3c288a782c8a7399f4c98` |
| `humaneval_plus` | `5ea35daeb34e28852c4bbcebd70013c1fc9a983fc8340255b073db1c89f8f41a` |
| `mbpp` | `ba9dc095fd6d8069762acb9c6ec0195f9d70a401598e6b0957686a5d3cefa05a` |
| `sallm` | `567d1edb5e3fe93015ed8dc39ce4a527ecb0f4fc47e5aabbde3cf4625c369bec` |
| `seccodebench_python` | `46f63ac088bc25eb4482c9afec8cfd25fa6a344f3a6427a32b7187c525e5bad9` |
| `securityeval` | `604f43902574dbc61afe56b81f3fe178bb71f3f5d5f41c35cf26c0289c8db3b5` |

The v2 source lock records:

| Item | Frozen value |
|---|---|
| Repository | `meta-llama/PurpleLlama` |
| Relative path | `CybersecurityBenchmarks/datasets/instruct/instruct-v2.json` |
| Resolved commit | `e36f132f4c4b952515a03b8bdb1275738a1fa28b` |
| SHA-256 | `df19f7c51911d46d0ae5c069b7093728db8e682890a44317a211ac61cb02c181` |
| Size | 3,006,400 bytes |
| Parsed records | 1,681 |

Before trusting a reused source, recompute its SHA-256 and compare it with the lock.
A mismatch is an error; do not update the lock merely to make the run proceed.

## Artifact meanings

Every published run directory is immutable and contains:

| Artifact | Meaning |
|---|---|
| `config.json` | Frozen effective audit configuration. |
| `commands.jsonl` | Exact logical argv and working directory. |
| `environment.json` | Python, machine, paths, Git commit/branch/dirty paths, lineage. |
| `run.log.jsonl` | Ordered phase completion log. |
| `file-inventory.jsonl` | Source/snapshot coordinates, byte sizes, hashes, migration status, v2 lock. |
| `record-audit.jsonl` | Per-record prompt evidence, language, CWE, neutrality, functional and cluster fields. |
| `duplicate-groups.jsonl` | Exact/normalized prompt-equivalence evidence edges. |
| `cluster-summary.jsonl` | Conservative task-cluster assignments and independence status. |
| `split-simulations.jsonl` | Frozen 50/50, 60/40 and 70/30 cluster-disjoint assignments and summaries. |
| `dataset-role-summary.jsonl` | Evidence-supported roles plus explicit blockers. |
| `failures.jsonl` | Structured record/phase failures; empty means zero recorded failures. |
| `report.json` | Machine-readable status, counts, compact split/role facts and stable digest. |
| `report.md` | Human-readable evidence tables and non-freezing caveats. |

`status=COMPLETE` means all selected source records passed implementation parsing and
reporting. It does not mean every record is research-eligible. Interpret progress as:

- `completed`: records that reached the audit output;
- `running`: records currently being processed;
- `failed`: malformed/rejected records or explicit implementation failures;
- `unresolved`: records needing CWE, neutrality, or independence adjudication;
- `pending`: selected records not yet processed;
- `records_per_second` and `eta_seconds`: runtime diagnostics excluded from the
  stable digest.

## Frozen Stage 0 evidence

The final combined inventory contains 3,048 records:

| Dataset | Records |
|---|---:|
| APPS | 200 |
| ClassEval | 60 |
| CWEval | 119 |
| CWEval Python | 25 |
| CyberSecEval discover-adv | 260 |
| CyberSecEval instruct v2 | 1,681 |
| CyberSecEval secure-code | 150 |
| HumanEval | 80 |
| HumanEval+ | 80 |
| MBPP | 120 |
| SALLM | 100 |
| SecCodeBench Python | 52 |
| SecurityEval | 121 |

Language counts are C 233, C++ 263, C# 218, Go 19, Java 164, JavaScript 267,
PHP 151, Python 1,555, and Rust 178. The deterministic neutrality screen reports
2,931 candidate-neutral, 16 obvious-conflict, and 101 unresolved records. Functional
evidence is absent for 2,508 records and present-but-unvalidated for 540; no executable
functional contract was validated by this stage. CWE evidence contains 2,456 resolved
assignments and 592 unresolved records. CWE assignments can exceed record counts when a
record has multiple labels.

Duplicate evidence contains 608 exact-prompt edges and 608 normalized-prompt edges,
covering 346 unique digest groups of each type. No fuzzy edge was accepted. The
conservative clustering result has 2,486 independent clusters and 85 unresolved
clusters.

| Split | Independent | Discover | Confirm | Unresolved | Floor 20 met |
|---|---:|---:|---:|---:|---|
| 50/50 | 2,486 | 1,201 | 1,285 | 85 | yes |
| 60/40 | 2,486 | 1,521 | 965 | 85 | yes |
| 70/30 | 2,486 | 1,760 | 726 | 85 | yes |

The security-labelled datasets are currently security-only secondary, Oracle
calibration, and extractor/TSG evaluation candidates. Their shared explicit blocker
is the absence of a validated executable functional contract. General functional
benchmarks remain pending because CWE scope is absent or unresolved and no contract
was validated in this audit. These are role recommendations, not final exclusions.

CyberSecEval exact normalized-prompt relationships are:

| Metric | Count |
|---|---:|
| Legacy discover-adv unique | 260 |
| Legacy secure-code unique | 150 |
| Exact overlap between the legacy 150/260 collections | 150 |
| v2 unique prompts | 1,679 |
| v2 overlap with legacy secure-code | 131 |
| v2 overlap with legacy discover-adv | 219 |
| v2 overlap with the legacy union | 219 |

## Stable-digest and byte comparison

Compare `report.json` stable digests first. Then compare the eight stable artifacts;
runtime/environment/report presentation files intentionally differ by run identity,
rate, or lineage.

Use the verified PowerShell form below. Do not pipe directly from the closing brace of
`foreach`; assign the rows first.

```powershell
$root = 'D:\MyCode\Causal\.worktrees\dataset-availability-audit\runs\dataset-audit'
$left = 'stage0-combined-20260810-07'
$right = 'stage0-combined-20260810-08'
$files = @(
  'config.json', 'file-inventory.jsonl', 'record-audit.jsonl',
  'duplicate-groups.jsonl', 'cluster-summary.jsonl',
  'split-simulations.jsonl', 'dataset-role-summary.jsonl', 'failures.jsonl'
)
$rows = foreach ($file in $files) {
  $a = (Get-FileHash -Algorithm SHA256 -LiteralPath "$root\$left\$file").Hash
  $b = (Get-FileHash -Algorithm SHA256 -LiteralPath "$root\$right\$file").Hash
  [pscustomobject]@{ File = $file; Match = ($a -eq $b); SHA256 = $a }
}
$rows | Format-Table -AutoSize
```

For `-07` and `-08`, all eight `Match` values are `True`, and both stable digests are
`2d5c16c613988dffd7f9a9299bcb7a43ef8fab6cc91ad45ae0b8e99c11cc38a8`.

## Failure recovery and error ledger

On any failure:

1. Preserve the final, failed, or `.staging` directory exactly as it is.
2. Read `run.log.jsonl`, `failures.jsonl`, `environment.json`, and the terminal error.
3. Distinguish source defects, missing metadata/contracts, unresolved adjudication,
   upstream unavailability, operator errors, and implementation defects.
4. Repair only the implementation/operator issue in this stage. Do not fabricate
   metadata, security labels, or functional contracts.
5. Validate on the smallest reproducer, then targeted tests, then a new full run ID.
6. Link the corrected run with `--supersedes-run-id` and verify all missing/failed
   tasks are accounted for.

The preserved 2026-08-10 error history is:

| Event | Diagnosis | Recovery/status |
|---|---|---|
| Diagnostic `ConvertFrom-Json` failed on case-insensitive keys | PowerShell object conversion was unsuitable for source records with colliding key case | Replaced only the diagnostic reader with explicit UTF-8 Python JSON parsing; source bytes unchanged. |
| First legacy full run exceeded the outer tool timeout | Unbounded pairwise fuzzy clustering was effectively quadratic | Preserved `.stage0-legacy-full-20260810-01.staging`; added bounded candidate blocks and stress tests. |
| GitHub REST metadata returned HTTP 403 | Anonymous API rate limit, not a missing source | Preserved `stage0-combined-20260810-01`; added a fail-closed `git ls-remote --refs` fallback only for 403/429. |
| `stage0-combined-20260810-02` acquired v2 but reported legacy-only counts | JSON-array v2 payload was not passed into the shared adaptation pipeline | Preserved the run; added array adaptation/inclusion tests and reran. |
| A patch temporarily misplaced an `elif` in artifact validation | Local editing defect detected before real execution | Repaired immediately; targeted tests passed before any new audit. |
| The first v2 rerun attempt used a one-second command timeout | Operator supplied an inadequate outer timeout | Preserved `.stage0-combined-20260810-04.staging`; reran as `-05` with a bounded 180-second limit. |
| Initial evidence report omitted split/role tables | Semantic review found conclusions were not locally inspectable | Added tested evidence tables; preserved earlier reports. |
| `stage0-combined-20260810-06` displayed `Datasetrole.*` labels | Real enum rendering differed from the test's plain strings | Added a real-enum regression test and stable professional labels; reran as `-07`/`-08`. |
| A read-only command referenced `split.py` instead of `splits.py` | Operator path typo | Corrected the path; no files changed. |
| Ruff commands failed | The fixed virtual environment and system PATH do not contain Ruff | Did not mutate the environment; used compile, tests, line-width check, and `git diff --check`; retain Ruff as an explicit environment gap. |
| A diagnostic `Path.read_text()` used the Windows default encoding | GBK could not decode UTF-8 punctuation | Reissued with `encoding='utf-8'`; no artifact changed. |
| PowerShell hash comparison used an empty pipeline element twice | The closing `foreach` brace was piped directly instead of assigning its output | Reused and froze the `$rows = foreach (...)` form above; audit results were never modified. |
| Final full-suite wait was interrupted after roughly 38 minutes | The quiet test process had produced no recoverable summary; after interruption its detached child continued running | Did not restart it. Confirmed the exact pytest parent/child, stopped only those two processes at 15:51 +08:00 after about 48 minutes total wall time, and recorded the gate as indeterminate. |
| The first process-stop command returned exit code 1 with no text | Its final `Get-Process` verification found no matching process after the stop | A separate read-only CIM check confirmed both targeted pytest processes were gone; unrelated Python processes were untouched. |

## Verification gates

After any implementation change, run the smallest relevant tests first. Before
declaring Stage 0 complete, run:

```powershell
$env:PYTHONPATH = 'src'
D:\MyCode\Causal\.venv\Scripts\python.exe -m pytest `
  tests\dataset_audit `
  tests\test_jsonl_stage_transaction.py `
  tests\test_artifact_store.py `
  tests\test_packaging.py -q
```

Then run one final repository suite:

```powershell
$env:PYTHONPATH = 'src'
D:\MyCode\Causal\.venv\Scripts\python.exe -m pytest -q
```

Real Semgrep/Bandit and RFCI integration are not rerun unless ordinary tests indicate
an affected boundary, because the dataset audit does not modify Oracle or RFCI code.
Record the exact pass/skip/fail counts, duration, commit, working directory, and logs
before claiming completion.

### 2026-08-10 verification record

- Targeted and adjacent command: **134 passed, 1 skipped in 13.04 seconds**.
- Final repository command: **indeterminate, not passed and not failed**. The quiet
  run was user-interrupted after roughly 38 minutes and had no recoverable pytest
  summary. Its residual parent/child processes were stopped at 15:51 +08:00 after
  approximately 48 minutes total wall time. The command was not restarted.
- Available static gates: Python compilation passed, changed Python files had no
  lines over the configured 100-column limit, and `git diff --check` passed.
- Ruff gate: not run because Ruff is absent from both the fixed virtual environment
  and system PATH; no dependency was installed merely to alter the validation state.
