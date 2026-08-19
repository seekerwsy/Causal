# Phase 0 contract checkpoint validation

Date: 2026-08-20 (Asia/Shanghai)

## Execution context

- Machine: `DESKTOP-ES5QORS`
- Worktree: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`
- Branch: `codex/phased-exploration-v3`
- Parent before this checkpoint: `3af2387`
- Python: `3.12.13`
- Interpreter: `D:\MyCode\Causal\.venv\Scripts\python.exe`

## Checkpoint scope

This checkpoint adds the first prospective Phase 0 contracts without changing the
legacy v1 runtime:

1. immutable, semantic-cluster-exclusive membership for all eight evidence pools;
2. four-valued context and feature states, atomic ADD/REMOVE eligibility, shared
   candidate-universe and realization-policy records;
3. decomposed safety/functionality outcomes and a semantic-cluster-weighted ITT
   estimator with whole-cluster bootstrap support.

The runtime request/provenance schema and simultaneous multiplicity layer are still
pending and are not implied by this checkpoint.

## Commands and results

The first combined test invocation used the repository virtual environment without
binding the new worktree's `src` directory. Collection failed with three
`ModuleNotFoundError` errors. This was diagnosed as an environment-path error; no
test body ran and no code change was used to conceal it.

The corrected targeted validation was:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
& D:\MyCode\Causal\.venv\Scripts\python.exe -m pytest `
  tests/test_phased_pool_partition.py `
  tests/test_policy_v2_contracts.py `
  tests/test_outcomes_itt_v2.py -q
```

Result: `44 passed in 0.47s`.

Static validation was:

```powershell
uvx ruff check `
  src/secaware/phased_exploration `
  src/secaware/schema/policy_v2.py `
  src/secaware/schema/outcomes_v2.py `
  src/secaware/analysis/itt_v2.py `
  tests/test_phased_pool_partition.py `
  tests/test_policy_v2_contracts.py `
  tests/test_outcomes_itt_v2.py
```

Result after applying the reported mechanical import/export ordering fixes:
`All checks passed!`.

No full-suite test was run for this checkpoint. The validation intentionally remains
targeted while the adjacent runtime schema is still being implemented.

## Status at checkpoint

- Completed components: 3 (pool partition, policy/realization, outcome/ITT base)
- Running but excluded from this commit: 1 (runtime request/provenance schema)
- Unresolved test failures in committed scope: 0
- Pending components: runtime schema; combined adjacency regression; multiplicity and
  simultaneous inference; Phase 1 data inventory/adjudication
