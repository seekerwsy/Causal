# JCI requirement-policy study

The active method on `codex/jci-framework` is specified in
[the JCI method](docs/jci-method.md). It learns Atomic requirement policies from
randomized task outcomes, uses conservative JCI structure as finite regularization,
selects policies on separate calibration tasks, and evaluates held-out policy value.
The evidence remains bounded method research. Formal provider execution is inactive.

## Reproduce and verify

Use Python 3.12 and R with pcalg 2.7.12 and jsonlite. Run from the repository root:

```text
python -m pip install -e ".[dev]"
python -m pytest -q --rscript=PATH_TO_RSCRIPT
python -m prompt_mechanism_study study smoke results/NEW_SMOKE --rscript PATH_TO_RSCRIPT
python -m prompt_mechanism_study study verify-jci-reliability results/NEW_SMOKE --workers 2
```

Set `OPENBLAS_NUM_THREADS=1` and `OMP_NUM_THREADS=1`. Install R packages into a
library available to R; the backend also reads `.codex-runtime/r-lib`.
The smoke executes four SCM learning repetitions, twelve real conservative FCI
searches, the complete policy consumers, exact value evaluation and simultaneous
comparisons. Its evidence identity is `NON_CLAIM_METHOD_REPRODUCTION`.

## Study commands

| Command after `study` | Operation |
| --- | --- |
| `jci-reliability OUTPUT --plan PLAN --rscript RSCRIPT` | Execute a frozen SCM comparison; `--limit` bounds a partial reproduction |
| `verify-jci-reliability OUTPUT` | Independently reconstruct randomization, CI statistics, fits, decisions and comparisons |
| `jci-replay OUTPUT --plan PLAN --rscript RSCRIPT` | Learn from budgeted original model outcomes, confirm selected candidates and evaluate separate test tasks |
| `verify-jci-replay OUTPUT` | Reconstruct the real-outcome replay, fixed slots, request budgets and task-level evaluation |
| `diagnose-jci-population PARENT OUTPUT --rscript RSCRIPT` | Query exact SCM independence and its graphical implications |

New executions use new output directories. An identical partial execution can
resume with its saved configuration and source identity. Verification checks the
archived execution source and independently reconstructs its results; the current
verifier has its own recorded identity.

## Evidence

The [reliability study](docs/experiments/2026-10-14-jci-reliability-results.md)
completed 3,072 independent SCM repetitions. All 384 simultaneous comparison
intervals include zero; no registered condition established reliable JCI value
increment. The [budget replay](docs/experiments/2026-10-14-jci-budget-replay-results.md)
uses real historical model outcomes and retains its post-hoc evidence identity.
Neither study establishes natural-task transfer or complete functional preservation.

The [reviewer guide](docs/reviewer-guide.md) maps the seven stages, saved records
and ten core files. The [test guide](tests/README.md) gives the current checks.
Earlier Atomic and JCI studies retain their frozen reports and source archives;
their repository implementation is available at `main` commit `d304d4ec`.
