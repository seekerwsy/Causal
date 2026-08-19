# Phase 0 outcome and inference local checkpoint

Date: 2026-08-20 (Asia/Shanghai)

## Execution context

- Machine: `DESKTOP-ES5QORS`
- Worktree: `D:\MyCode\Causal\.worktrees\dataset-availability-audit`
- Branch: `codex/phased-exploration-v3`
- Parent before this checkpoint: `e259038`
- Python: `3.12.13`
- Interpreter: `D:\MyCode\Causal\.venv\Scripts\python.exe`

## Checkpoint scope

This local checkpoint closes the canonical confirmation-block coordinate drift
between policy, runtime, and outcome records; propagates the complete confirmation
coordinates through the producer chain; aligns request-randomness domains; and adds
an exact single-assignment outcome assembler with fail-closed provenance joins.

It also preserves an initial implementation of content-addressed simultaneous
inference plans and studentized max-|T| inference. Those two inference modules have
passed formatting, lint, and import checks, but do not yet have dedicated behavioral
tests. Therefore this checkpoint is explicitly work in progress and does not mark
Phase 0 or the inference gate complete.

## Commands and results

Targeted runtime, outcome, ITT-regression, and assembler tests:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
& D:\MyCode\Causal\.venv\Scripts\python.exe -m pytest `
  tests/test_runtime_v2_contracts.py `
  tests/test_outcomes_itt_v2.py `
  tests/test_outcome_assembler_v2.py -q
```

Result: `26 passed in 0.46s`.

Static validation across every changed Python file:

```powershell
uvx ruff check <all changed Python paths>
uvx ruff format <all changed Python paths>
uvx ruff check <all changed Python paths>
```

Result: five files were formatted and the final check reported
`All checks passed!`.

Inference-module import smoke check:

```powershell
$env:PYTHONPATH = (Join-Path (Get-Location) 'src')
& D:\MyCode\Causal\.venv\Scripts\python.exe -c `
  "from secaware.schema.inference_v2 import SimultaneousInferencePlanV2; from secaware.analysis.simultaneous_v2 import run_simultaneous_inference_v2; print('v2 inference imports: ok')"
```

Result: `v2 inference imports: ok`.

The first smoke-check command incorrectly requested the nonexistent name
`run_simultaneous_max_t_v2`; inspection identified the implemented public function
as `run_simultaneous_inference_v2`, and the corrected command passed. No code change
was needed for that command error.

No full-suite test, paid API call, model execution, or remote-server experiment was
run for this checkpoint.

## Remaining gate work

- Add behavioral and adversarial tests for simultaneous inference.
- Bind inference to frozen eligible-population, policy-support, assignment, and
  exact-coverage manifests rather than caller-supplied self-consistent rows alone.
- Implement and test realization-robustness inference.
- Add the population/randomization manifests and a replayable v2 end-to-end path.
