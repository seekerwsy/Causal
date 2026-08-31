# Reviewer guide

## Status and entry point

There is one active method: prospective protocol
`phase-context-policy-v3`, currently `SPECIFIED_DRAFT`. Its schema-3 core is
implemented and tested; formal inputs have not been accepted and formal
provider execution remains disabled.

The sole executable study entry point is:

```text
prompt-mechanism-study study smoke OUTPUT
```

It invokes `run_target_reviewer_smoke` in
`src/prompt_mechanism_study/target_workflow.py`. The smoke is deterministic,
uses synthetic measurements, performs zero provider calls, and can produce only
a `NON_CLAIM_TEST_ARTIFACT`. The only other study-facing operation is
read-only verification:

```text
prompt-mechanism-study study verify-result OUTPUT
```

## Seven-stage path

| Stage | Frozen input | Output | Implementation |
| --- | --- | --- | --- |
| Representation | source records, data roles, catalog and Prompt TSG evidence | deduplicated task units and canonical policy identities | `representation.py`, `mechanisms.py` |
| Prioritization | DISCOVERY-only observations and accepted selector profiles | support-qualified Full/Ablation/baseline fixed slots | `prioritization.py`, `interaction_selector.py`, `rq1_baselines.py` |
| Hypothesis freeze | accepted qualification, budget, candidate folds and fixed slots | discovery freeze, unique confirmation union, model-bound dispatch and confirmation freeze | `study_design.py`, `prioritization.py` |
| Intervention/randomization | frozen task-policy arm digests and model-effect coordinates | deterministic balanced assigned-arm blocks | `randomization.py` |
| Measurement | frozen assigned prompt and evaluator identities | code validity, Security Oracle and blinded functionality records | `measurement.py` |
| Outcome assembly | every assignment plus terminal measurement or infrastructure failure | total assigned-arm outcome ledger | `outcomes.py`, `inference.py` |
| Inference/reporting | frozen ITT plan, total ledger and study-freeze index | Atomic/Pair simultaneous families, five statuses, fixed-K RQ tables and independent receipt | `inference.py`, `selector_analysis.py`, `verification/verifier.py` |

The path is linear and typed. There is no active schema-1/2 runner, selector
study, successor experiment, factorial experiment, or compatibility wrapper in
the CLI or default tests.

## Scientific invariants

A reviewer should confirm that:

- Prompt TSG edges encode semantics, never causal structure. Generated code is
  an independently measured result, not a primary-PAG variable or mediator.
- `QUAL_DEV`, one-shot `QUAL_ACCEPT`, `DISCOVERY`, `CONFIRMATION`, and
  `LEGACY_ONLY` are separated at both task-unit and near-duplicate-group
  levels.
- Discovery design, folds, selector definitions and budget are frozen before
  discovery outcomes. Fixed slots, their unique union, protocolization,
  task-policy bundles, assignments, estimands and report rules are frozen
  before confirmation outcomes.
- A semantic `policy_key` is model-independent. A scientific effect is bound
  to `(policy_key, model_id)`; model dispatch is not crossed with the model
  list a second time.
- Atomic Full and RD-only differ only in FCI structural evidence. Pair Full and
  No-Relation share the compatibility-first universe and RD coordinates; only
  Full reads relation support.
- Blinded Expert and seeded Random baselines use the same eligible universe,
  model coordinate and K, then enter the same fixed-slot, union, dispatch and
  confirmation path.
- ADD and REMOVE source gates are operation-specific. Unresolved or ineligible
  records remain explicit rather than silently disappearing.
- Each task-policy block contains all four canonical arms, unique request
  slots, frozen variant digests and replayable nullable provider seeds.
- Assigned-arm, deduplicated-task-unit ITT is primary. Post-assignment
  diagnostics never filter the denominator.
- Every assignment is partitioned exactly once into an outcome or
  infrastructure failure. Invalid code, Oracle `unknown`, functional failure,
  and terminal output retain their frozen meanings.
- The primary secure-code yield is reported separately from validity,
  evaluability, unknown coverage, functionality and joint success.
- Atomic and Pair effects use separate frozen simultaneous families and the
  direction-free five-status rule. RQ2 is the descriptive fixed-denominator
  Full-minus-Ablation Yield@K difference.
- Formal claim authorization requires accepted prospective lineage and the
  exact frozen package. `specified`, `implemented`, `tested`, `executed`
  and `reported` are never conflated.

## Reading order

The normative specification is
`docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`.
The active implementation can then be read in this ten-file order:

1. `src/prompt_mechanism_study/target_workflow.py`
2. `src/prompt_mechanism_study/representation.py`
3. `src/prompt_mechanism_study/prioritization.py`
4. `src/prompt_mechanism_study/interaction_selector.py`
5. `src/prompt_mechanism_study/study_design.py`
6. `src/prompt_mechanism_study/randomization.py`
7. `src/prompt_mechanism_study/measurement.py`
8. `src/prompt_mechanism_study/inference.py`
9. `src/prompt_mechanism_study/selector_analysis.py`
10. `src/prompt_mechanism_study/verification/verifier.py`

The verifier entry delegates only to verification-owned modules for package
integrity, qualification/design replay, Atomic/Pair effect reconstruction, and
report authorization. Those modules may import frozen record types and exact
serialization helpers, but never production estimators or table builders.

```text
verification/
  integrity.py       exact files, typed decoding, package index
  qualification.py   power, budget, and provider preflight replay
  design.py          assignment/randomization and freeze replay
  effects.py         Atomic/Pair effects, status, and Yield@K replay
  reporting.py       RQ tables and claim authorization replay
  verifier.py        the only package-level orchestration entry
```

Supporting modules provide shared records, exact artifact I/O, outcome
derivation, local security profiles, functional review, and optional RQ1
baselines; they do not create a second orchestration path.

## Reproduction and verification

Run the fast reviewer suite:

```text
.venv\Scripts\python.exe -m pytest -m reviewer -q
```

Run the milestone smoke and all retained tests:

```text
.venv\Scripts\python.exe -m pytest -m milestone -q
.venv\Scripts\python.exe -m pytest -q -o addopts=""
```

Run and independently reload the smallest representative package:

```text
prompt-mechanism-study study smoke REVIEWER_SMOKE_RESULT
prompt-mechanism-study study verify-result REVIEWER_SMOKE_RESULT
```

The verifier requires the exact schema-3 file set, reconstructs typed records,
and independently replays role lineage, budget, both freezes, fixed slots,
model-bound dispatch, arm order, variant and seed binding, assigned-arm ITT,
simultaneous families, five statuses, Yield@K, claim authorization and RQ
tables. It never starts provider calls.

A future frozen full reproduction must also provide every raw response,
measurement, input identity, environment, command and provider-ledger artifact
referenced by its index. No such formal target package exists at this
checkpoint.

## Archive boundary

The default reviewer path excludes historical selector/successor/factorial
runners, deployment recovery, calibration exploration and incident-specific
tests. Frozen historical bundles are not rewritten or reinterpreted. Their
locations and source recovery boundary are documented in
[legacy artifacts](archive/legacy-artifacts.md).
