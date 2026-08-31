# Test suite

The maintained suite is organized by scientific stage and invariant, not by
historical protocol version.

## Reviewer layer

```text
.venv\Scripts\python.exe -m pytest -m reviewer -q
```

This fast layer protects the data-role firewall, Prompt-TSG semantics,
operation-specific source gates, support/fold freezing, Atomic and Pair
Full/Ablation selectors, qualified Expert/Random baselines, fixed slots,
model-effect deduplication, deterministic arm assignment, total outcome
accounting, task-unit ITT, five statuses, fixed-K RQ tables, claim gating,
exact package writing, and independent replay.

## Milestone layer

```text
.venv\Scripts\python.exe -m pytest -m milestone -q
```

Milestones cover optional backend capability and the smallest end-to-end
closure. The schema-3 zero-network package smoke is also available through the
production CLI:

```text
prompt-mechanism-study target-study smoke REVIEWER_SMOKE_RESULT
prompt-mechanism-study target-study verify-result REVIEWER_SMOKE_RESULT
```

It traverses all seven stages with deterministic synthetic evidence, makes zero
provider calls, and is hard-bound to `tested` non-claim output.

## Complete retained suite

```text
.venv\Scripts\python.exe -m pytest -q -o addopts=""
```

Extended tests retain calibration, backend, boundary, and tamper checks that
protect the active schema-3 method or reviewer safety. Historical schema-1/2
runner and verifier tests are recoverable through Git and are not part of the
active suite.
