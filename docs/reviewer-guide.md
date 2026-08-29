# Reviewer guide

This repository exposes one active research method through the installed
`prompt-mechanism-study` command. The command's selector, successor, and
factorial subcommands are stage boundaries, not competing frameworks.

The normative protocol is the
[context-conditioned intervention policy framework](superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).
The active implementation accepts the prospective selector schema 2.1,
successor ADD/REMOVE studies, and factorial schema 1.1. Historical execution
code is not imported by the package or exposed by the CLI; immutable historical
result bundles remain available to the independent result verifier.

The review tree retains the active specification, current dataset-curation
records, Functional Judge qualification inputs, the two replayable factorial
result bundles, and their result notes. Superseded E2E deployments, server
runbooks, predecessor four-arm studies, implementation plans, and incident
chronology were removed from the live tree after commit `f94d109`; Git history
is their recovery boundary.

## Seven-stage artifact path

| Stage | Frozen input | Output | Main implementation |
| --- | --- | --- | --- |
| Representation | normalized source records and catalog | deduplicated task units and Prompt TSGs | `prompt_tsg.py`, `representation.py` |
| Prioritization | discovery task units and Prompt TSG support | shared candidate universe, ranked slots, optional pair selection | `prioritization.py`, `selector_experiment.py`, `interaction_selector_experiment.py` |
| Hypothesis freeze | selected coordinates, registry, provider and Oracle qualifications | exact hypotheses, prompt variants, adapter identities, seeds, endpoints, and analysis plan | `successor_experiment.py`, `factorial_experiment.py`, `qualification.py` |
| Intervention/randomization | frozen hypotheses or pairs | complete assigned-arm blocks and global execution order | `intervention.py`, `randomization.py` |
| Measurement | assigned prompt plus frozen adapters | raw responses, code validity, Security Oracle result, Functional Judge result | `measurement.py` |
| Outcome assembly | every randomized assignment and measurement | total assigned-arm ledger | `outcomes.py`, `workflow.py` |
| Inference/reporting | frozen plan and total ledger | task-unit ITT estimates, bounds, simultaneous intervals, report | `inference.py`, matching independent verifier |

The two runner modules are intentionally linear. Shared exact-JSON, hashing,
path-confinement, and bundle operations live in `artifact_io.py`; qualification
identity and power-plan checks live in `qualification.py`. Pre-outcome
factorial semantics are replayed by `factorial_freeze.py`. Result verifiers do
not reuse the production estimators.

## Scientific invariants

A review should confirm all of the following:

- Prompt TSG edges encode prompt semantics, never causal structure.
- Generated code supplies independently measured security and functionality
  outcomes; it is not a mediator or primary-PAG variable.
- Candidate selection, task support, hypotheses, exact variants, adapters,
  seeds, endpoints, estimands, and multiplicity are frozen before outcomes.
- Atomic and pair discovery states are recomputed from the embedded catalog,
  prompt, and Prompt TSG evidence; a producer-supplied binary state is never
  accepted as representation evidence by itself.
- ADD and REMOVE use operation-specific target/control coding. Pair candidates
  enter the selector only when their frozen relation is factorial-compatible.
- Every task-unit/realization/model block has complete assigned-arm support.
- Assigned-arm, deduplicated-task-unit ITT is primary; task units are equally
  weighted.
- Fidelity, semantic compliance, generation success, and non-target drift are
  diagnostics and never denominator filters.
- Invalid code, Security Oracle `unknown`, functional failure, and terminal
  model output remain in the assignment ledger under their frozen semantics.
- Secure-code yield is separate from validity, evaluability, unknown coverage,
  functionality, and joint success.
- A functionality non-inferiority claim requires a pre-outcome study-specific
  power qualification; a favorable point estimate alone cannot authorize it.
- Smoke, demo, calibration, and development-canary outputs cannot be promoted
  to confirmatory evidence.
- A statistically nonadditive pair is first a Prompt-policy response-surface
  result. A mechanism-interaction label additionally requires a prospectively
  frozen `mechanism_eligible` Oracle scope; `policy_only` cannot be promoted by
  significance.

## Reading order

The scientific core can be reviewed in ten files:

1. `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`
2. `src/prompt_mechanism_study/prompt_tsg.py`
3. `src/prompt_mechanism_study/mechanisms.py`
4. `src/prompt_mechanism_study/prioritization.py`
5. `src/prompt_mechanism_study/selector_experiment.py`
6. `src/prompt_mechanism_study/intervention.py`
7. `src/prompt_mechanism_study/randomization.py`
8. `src/prompt_mechanism_study/measurement.py`
9. `src/prompt_mechanism_study/inference.py`
10. `src/prompt_mechanism_study/workflow.py`

For execution details, then read only the relevant linear runner and its
matching verifier: `successor_experiment.py`/`successor_verify.py` or
`factorial_experiment.py`/`factorial_verify.py`. Selector result analysis is in
`selector_analysis.py`; outcome-blind selection and bridge freezing remain in
`selector_experiment.py`.

## Reproduction commands

Run the default reviewer-facing invariant suite:

```text
python -m pytest -q
```

Run the smallest active zero-network reproduction after a method-level change:

```text
python -m pytest -q -m milestone tests/test_factorial_reviewer_smoke.py
```

This smoke freezes two task units, one pair, both application orders, four
cells, and one fixture model: 16 assignments in total. It runs the real local
Security Oracle, writes only to the test temporary directory, and disables
scientific and functionality-power claims.

Verify a tracked frozen result at both artifact and scientific levels:

```text
prompt-mechanism-study verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3

prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3
```

The second command independently replays stored provider responses through
code extraction, syntax/compilation, Security Oracle, Functional Judge,
measurement, total-ledger assembly, and inference without another provider
call. The scaffold-repair reference bundle can be substituted in the same
commands.

For a new active factorial study, preflight, freeze, and run are distinct:

```text
prompt-mechanism-study factorial-experiment preflight PREFLIGHT \
  --repository-root . --config ACTIVE_SCHEMA_1_1_CONFIG

prompt-mechanism-study factorial-experiment freeze FREEZE \
  --repository-root . --config ACTIVE_SCHEMA_1_1_CONFIG

prompt-mechanism-study factorial-experiment run RESULT \
  --repository-root . --config ACTIVE_SCHEMA_1_1_CONFIG --freeze FREEZE
```

Provider credentials and deployments are external. The reviewer artifact does
not include server administration, retries, recovery machinery, calibration
exploration, or temporary checkpoints.

## Current evidence status

The successor, schema-2.1 selector, pair selector, and generalized schema-1.1
factorial paths are implemented and reviewer-tested. They have not yet produced
a new claim-bearing provider run. The tracked schema-1.0 factorial results are
formal historical evidence and remain reproducible through the verifier, but
are not reinterpreted under schema 1.1. Passing a test establishes neither
execution nor an effect.
