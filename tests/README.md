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

The current collection contains 113 test functions and 130 parameterized test
cases. Only 55 cases form the default reviewer gate; the remaining cases are
full-suite calibration, boundary, backend, and tamper checks. Test count is not
used as a retention criterion: each retained test must protect a distinct
scientific invariant, transformation boundary, or independent verification
failure mode.

| Test area | Files | Why it remains |
| --- | --- | --- |
| Active schema-3 closure | `test_representation.py`, `test_target_workflow.py`, `test_target_inference.py`, `test_artifacts.py` | policy identity, seven-stage closure, assigned-arm ITT, report gating, and independent tamper detection |
| Discovery and freeze | `test_discovery_support.py`, `test_selector_study.py`, `test_interaction_selector.py`, `test_study_design.py` | data-role firewalls, Full/Ablation equality constraints, fixed slots, power, budget, and two freeze moments |
| Outcome-free data preparation | `test_datasets.py`, `test_curation.py`, `test_eligibility.py`, `test_task_unit_data.py` | source accounting, deduplication authority, blind curation, eligibility, and task-unit compilation |
| Representation and measurement qualification | `test_prompt_tsg.py`, `test_prompt_contract.py`, `test_security_profiles.py`, `test_functional_judge_gate.py` | evidence binding, finite semantics, Oracle unknown handling, and blinded functionality boundaries |

## Milestone layer

```text
.venv\Scripts\python.exe -m pytest -m milestone -q
```

Milestones cover optional backend capability and the smallest end-to-end
closure. The schema-3 zero-network package smoke is also available through the
production CLI:

```text
prompt-mechanism-study study smoke REVIEWER_SMOKE_RESULT
prompt-mechanism-study study verify-result REVIEWER_SMOKE_RESULT
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
