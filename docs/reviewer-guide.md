# Reviewer guide

## Status and entry point

There is one active method: prospective protocol
`phase-context-policy-v3`, currently `SPECIFIED_DRAFT`. Its schema-3 core is
implemented and tested; formal inputs have not been accepted and formal
provider execution remains disabled.

Before the seven scientific stages, the target schema now supports one
optional D0 data-preparation decision: a qualified, outcome-blind coverage
census may either accept the existing Discovery population, execute one
bounded selector-blind natural-task supplementation round, or end in
`COVERAGE_BLOCKED`. The repository currently implements and tests the D0
records and validators only. The terminal reviewer data set is now tracked at
`data/dataset-curation/reviewer-task-unit-dataset-v5`; its manifest SHA-256 is
`33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`.
The outcome-blind source population is frozen as the 381
`QUALITY_INCLUDED` Python task units. Technical readiness (currently 101) is
diagnostic and is not an admission rule. The repository still does not assign
new formal roles or generate formal Prompt TSGs while representation profiles,
author thresholds, power, and budget remain unfrozen.

The sole prospective provider/model coordinate is now Beijing Alibaba Bailian
`qwen3.7-flash-2026-07-15` for every external LLM role. Dynamic aliases,
fallbacks, replication models, and automatic retries are forbidden. This is an
author selection, not provider authorization: every assigned Flash role must
still pass its prospective qualification, and historical Qwen3.7-Max judge
evidence remains legacy-only.

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
| Prioritization | one accepted Discovery-population lineage, DISCOVERY-only observations and accepted selector profiles | unified Atomic/Pair discoverability, support-qualified Full/Ablation/baseline fixed slots | `prioritization.py`, `interaction_selector.py`, `rq1_baselines.py` |
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
- D0 follows representation qualification and capacity recovery. Its pre
  census, plan, optional receipt and post census bind one population version,
  source/retrieval limits, exposure and deduplication policy, role policy,
  lineage quotas, stopping rule and future-evaluation reservation. It cannot
  read FCI/PAG, RD, rank, Full/Ablation membership, relation support, or any
  outcome, and it cannot create paraphrases, interventions or synthetic cells.
- Atomic and Pair candidates carry one typed discoverability decision tied to
  the same accepted population. Pair eligibility reads no Atomic support,
  adjacency, rank or selection result; a pure interaction can proceed on its
  own compatible four-cell support and folds.
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
- Context modifiers are Stage-III secondary analyses, not selectors or policy
  identity. Because exact task assignments, joint bootstrap and multiplicity
  are not yet author-frozen, the active record is
  `BLOCKED_NO_FROZEN_CONTEXT_RULE` and emits no context table.
- Pair results retain their independently verified four-cell response surface.
  Because deterministic label predicates are not yet author-frozen, the
  classification status is `BLOCKED_NO_FROZEN_PREDICATE` and the response
  pattern itself is null; Atomic records say `NOT_APPLICABLE`.
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
tables, context-analysis readiness, and Pair response surfaces/classification
status. It never starts provider calls.

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
