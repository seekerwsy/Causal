# Phase 0 runtime provenance checkpoint validation

Date: 2026-08-20 (Asia/Shanghai)

## Execution context

- Machine: `DESKTOP-ES5QORS`
- Worktree: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`
- Branch: `codex/phased-exploration-v3`
- Parent before this checkpoint: `16348bd`
- Python: `3.12.13`
- Interpreter: `D:\MyCode\Causal\.venv\Scripts\python.exe`

## Checkpoint scope

This checkpoint adds the immutable v2 runtime records that connect a natural or
randomized task assignment to generation, generated code, Oracle evaluation and
functional evaluation. Every record carries the regime, semantic task cluster,
task instance and request-randomness slot. Provider seeds are explicitly nullable.
Confirmation records require the hypothesis, realization specification, task-level
bundle and arm coordinates, while discovery records reject confirmation-only fields.

The producer-chain validator requires exact coordinate and content-addressed reference
joins. It does not upgrade legacy results or implement multiplicity-adjusted inference.

## Commands and results

Combined targeted regression across all Phase 0 checkpoint modules:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
& D:\MyCode\Causal\.venv\Scripts\python.exe -m pytest `
  tests/test_phased_pool_partition.py `
  tests/test_policy_v2_contracts.py `
  tests/test_outcomes_itt_v2.py `
  tests/test_runtime_v2_contracts.py -q
```

Result: `51 passed in 0.46s`.

Static validation:

```powershell
uvx ruff check `
  src/secaware/schema/runtime_v2.py `
  tests/test_runtime_v2_contracts.py
```

Result: `All checks passed!`.

No full-suite test was run. The next validation boundary is the adjacency regression
that connects these contracts to a minimal orchestrated Phase 0 execution path.
