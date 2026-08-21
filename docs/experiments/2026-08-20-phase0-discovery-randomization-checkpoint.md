# Phase 0 discovery, randomization, and inference checkpoint

Date: 2026-08-20 (Asia/Shanghai)

## Execution context

- Machine: `DESKTOP-ES5QORS`
- Worktree: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`
- Branch: `codex/phased-exploration-v3`
- Parent before this checkpoint: `3ad189f`
- Python: `3.12.13`
- Interpreter: `D:\MyCode\Causal\.worktrees\dataset-availability-audit\.venv\Scripts\python.exe`
- Ruff: `D:\MyCode\Causal\.worktrees\dataset-availability-audit\.venv\Scripts\ruff.exe`

## Checkpoint scope

This work-in-progress checkpoint preserves the Phase 0 implementation of:

- target-independent Prompt-TSG context queries;
- natural-discovery table contracts and table construction;
- atomic intervention bridges for ADD and REMOVE hypotheses;
- frozen eligible-population, randomization, and exact assignment-coverage manifests;
- manifest-bound task-clustered ITT estimation;
- studentized simultaneous max-|T| inference and realization-robustness checks; and
- an initial natural Prompt query/runtime observation assembler.

The natural observation assembler is syntax- and lint-valid but does not yet have
dedicated behavioral tests. Independent cross-module reviews are still in progress.
Accordingly, this is a local state-preservation commit, not Phase 0 acceptance and
not formal experimental evidence.

## Commands and results

The first validation attempt used
`D:\MyCode\Causal\.venv\Scripts\python.exe`. That interpreter's editable install
resolved `secaware` to `D:\MyCode\Causal\src` instead of the active worktree and did
not contain Ruff. The resulting import-collection failures were environmental and
were not treated as test results. The cause was verified by printing
`secaware.__file__`.

Validation was then repeated with the active worktree's interpreter and Ruff.

Targeted tests:

```powershell
& .\.venv\Scripts\python.exe -m pytest -q `
  tests/test_policy_v2_contracts.py `
  tests/test_runtime_v2_contracts.py `
  tests/test_outcomes_itt_v2.py `
  tests/test_outcome_assembler_v2.py `
  tests/test_context_queries_v2.py `
  tests/test_intervention_bridge_v2.py `
  tests/test_natural_discovery_table_v2.py `
  tests/test_population_randomization_v2.py `
  tests/test_simultaneous_inference_v2.py `
  tests/test_realization_robustness_v2.py `
  tests/test_tsg_motifs.py
```

Result: `143 passed in 2.63s`.

Static checks covered all 16 changed Python files:

```powershell
& .\.venv\Scripts\python.exe -m compileall -q `
  src/secaware/outcomes/discovery_assembler_v2.py
& .\.venv\Scripts\ruff.exe check <all changed Python paths>
& .\.venv\Scripts\ruff.exe format --check <all changed Python paths>
```

The assembler syntax check passed. The first Ruff pass found one import-style issue
in the new assembler (`Mapping` imported from `typing`); it was corrected to use
`collections.abc`. The final Ruff check reported `All checks passed!`, the format
check reported `16 files already formatted`, and `git diff --check` found no
whitespace errors.

No full-suite test, paid API call, model execution, or remote-server experiment was
run for this checkpoint.

## Work remaining before Phase 0 acceptance

- Add behavioral and provenance-drift tests for the natural observation assembler.
- Close any P0 findings from the independent cross-module reviews.
- Add the remaining v2 synthetic discovery/background-knowledge acceptance cases.
- Record a separate Phase 0 gate report after all required checks pass.
