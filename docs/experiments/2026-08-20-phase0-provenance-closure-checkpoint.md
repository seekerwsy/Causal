# Phase 0 provenance-closure checkpoint

Date: 2026-08-20 (Asia/Shanghai)

## Execution context

- Machine: `DESKTOP-ES5QORS`
- Worktree: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`
- Branch: `codex/phased-exploration-v3`
- Parent before this checkpoint: `3f34c18`
- Python: `3.12.13`
- Interpreter: `D:\MyCode\Causal\.worktrees\dataset-availability-audit\.venv\Scripts\python.exe`
- Ruff: `D:\MyCode\Causal\.worktrees\dataset-availability-audit\.venv\Scripts\ruff.exe`

## Checkpoint scope

This work-in-progress checkpoint preserves the Phase 0 implementation of:

- pre-outcome protocol roots and a run-level frozen hypothesis-by-model universe;
- exact source-inventory, semantic-cluster, eligible-population, intervention,
  realization, randomization, and execution-policy bindings;
- assignment-to-request-to-code-to-Oracle-to-functional-result provenance and
  total assignment accounting;
- provenance-closed task-clustered contribution construction;
- formal bootstrap minimums, fail-closed invalid-draw handling, simultaneous
  max-|T| result validation, and non-self-reported realization robustness;
- target-independent context-query and intervention read-set validation; and
- authenticated natural-discovery observations, producer-chain replay, and
  two-level cluster/slot resampling.

The changes close the reviewed counterexamples involving post-hoc outcome or arm
selection, deleted tasks/models/realizations, forged outcomes or producer IDs,
malformed context paths, actionable features overlapping a context-query read-set,
and raw repeated-slot rows entering conditional-independence analysis.

This is a local state-preservation commit. It is not Phase 0 acceptance, a formal
experiment run, or scientific evidence.

## Commands and results

Static validation covered every changed or newly added Python file:

```powershell
$files = @((git diff --name-only --diff-filter=ACM); `
  (git ls-files --others --exclude-standard)) | `
  Where-Object { $_ -like '*.py' }
& .\.venv\Scripts\python.exe -m py_compile $files
& .\.venv\Scripts\ruff.exe check $files
& .\.venv\Scripts\ruff.exe format --check $files
```

The first format check found seven files written with a different formatter
layout. The active worktree's pinned Ruff formatter was applied mechanically, and
the repeated syntax, lint, and format checks all passed: `All checks passed!` and
`23 files already formatted`.

Targeted regression command:

```powershell
& .\.venv\Scripts\python.exe -m pytest -q `
  tests/test_protocol_freeze_v2.py `
  tests/test_experiment_freeze_v2.py `
  tests/test_context_queries_v2.py `
  tests/test_intervention_bridge_v2.py `
  tests/test_population_randomization_v2.py `
  tests/test_simultaneous_inference_v2.py `
  tests/test_realization_robustness_v2.py `
  tests/test_confirmatory_contributions_v2.py `
  tests/test_authenticated_natural_discovery_v2.py `
  tests/test_natural_discovery_table_v2.py
```

Result: `83 passed in 171.25s`.

`git diff --check` was also run before staging. No full-suite test, paid API call,
model execution, remote-server experiment, or formal data analysis was run for
this checkpoint.

## Work remaining before Phase 0 acceptance

- Bind exact query-evidence artifacts into the pre-outcome protocol root.
- Add the global hypothesis-by-model simultaneous-inference runner for coordinates
  with different frozen eligible supports; do not replace it with a common-support
  intersection.
- Add the formal analysis orchestrator that consumes the run-level root and exact
  assignment evidence without caller-selected outcome, arm, model, or family.
- Add the remaining v2 synthetic SCM/background-knowledge acceptance cases.
- Run a completion audit and record a separate Phase 0 gate report.

The authenticated natural-discovery receipt currently embeds the complete scope,
which is safe but can require quadratic storage/validation work. A later CAS-backed
reference optimization may improve scaling without changing the frozen semantics.
