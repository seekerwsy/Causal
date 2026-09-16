# Reviewer guide

The single active method is the [Atomic protocol](protocol.md),
`phase-context-policy-v3`, still `SPECIFIED_DRAFT`. The implementation is a
research prototype; no formal effect-bearing result or qualified automatic TSG
accuracy is claimed. Pair research and its original reproduction path live on
[`codex/pair-interaction-research`](https://github.com/seekerwsy/Causal/tree/codex/pair-interaction-research)
at `e6833027`.

## Entry point and reproduction

With Python 3.12 and `dev,selectors,languages` extras installed:

```text
python -m pytest -q
prompt-mechanism-study study smoke NEW_OUTPUT_DIRECTORY
prompt-mechanism-study study verify-result NEW_OUTPUT_DIRECTORY
```

The suite already includes both smoke and independent verification. Run the
standalone commands only when a saved package is useful. The smoke calls
`target_workflow.run_target_reviewer_smoke`, writes all seven stages, and makes
zero provider calls. Its synthetic inputs and offline responses come from
`fixtures/reviewer_smoke.json`. It executes parsing, local security measurement
and functional-response validation, but does not establish evaluator accuracy,
FCI qualification, natural support or formal statistical power.

`study development OUTPUT --development-plan PLAN` executes an explicitly
bounded, authorized Atomic development plan. `study verify-development SAVED_RUN`
checks saved responses, assignment accounting and descriptive statistics without
provider calls. Development sign-flip/Holm tests are not the formal simultaneous
family. Historical Pair plans are not accepted by main.

## Seven stages

| Stage | Inputs | Outputs and boundary |
| --- | --- | --- |
| Representation | Actual system/user input, language, source-only semantic reference and catalog | Requirements with condition/object bindings; Atomic policies with exact source scope. TSG edges are not causal. |
| Prioritization | Frozen population, support/folds and qualified profiles; separate Discovery outcomes | Full and RD-only fixed-K ledgers. Only Full uses the FCI adjacency gate; both share RD scores. |
| Hypothesis freeze | Fixed slots, unique model effects, intervention/Oracle qualifications, power and budget | Shared dispatch, realizations and pre-outcome freeze. Empty/failure slots stay in K. |
| Intervention/randomization | Original task pool, allocated realization, complete four-arm bundles | Reproducible task/arm/model/seed assignments; failed allocations are retained without replacement. |
| Measurement | Assigned prompts and blinded evaluator contracts | Raw code, validity, secure/insecure/unknown, functionality and measurement failures. |
| Outcome assembly | Every assignment plus measurement or infrastructure failure | Complete assigned-arm ledger; no post-assignment denominator filter. |
| Inference/reporting | Frozen ITT plan, total ledger and fixed realization weights | Atomic effects, simultaneous intervals, statuses, Yield@K tables and independently verified provenance. |

Optional D0 is one bounded, outcome- and selector-blind round of natural source
preparation before Discovery. It cannot use feature states, candidate support,
ranks or outcomes to fill cells. Protected evaluation inputs stay protected.

## Source semantics and current limits

The [TSG workflow](tsg-workflow-stability.md) is the detailed implementation guide.
Source records preserve requirement composition, direct targets, subjects,
conditions and evidence before compilation. Ordinary source review may request
one local patch. Debug readings expose the structure; they do not prove the
model checked it correctly. The experimental detailed binding audit is not a
default paid component.

The [candidate guide](tsg-candidate-construction.md) covers equivalent-factor
normalization and exact, state-blind scope binding. It never splits source nodes,
repairs missing bindings or infers absence from unknown. Shared/unlocalized
unknowns can still block several candidates; unrelated localized unknowns need
not reject the whole task. An Atomic record is not automatically independently
editable: the intervention bridge must qualify the concrete edit.

Independent qualification freezes a source reference, profiles and thresholds
before extraction. Assertion review covers both missing meanings and unsupported
extra bindings; extractor self-approval is not the reference. Positivity consumes
that qualified representation and exact Atomic scope bindings. Unknown tasks
remain visible in coverage and failed support blocks selection. Existing exposed
diagnostic cases cannot retrospectively qualify a new method.

## What must remain invariant

- The task unit, deduplicated across sources, is the independent analysis unit.
- Policy identity is model independent; confirmation dispatch is model bound.
- ADD and REMOVE have different source-state requirements and identities.
- Every selector keeps its original K; shared effects run once and fan back to slots.
- Every committed assignment has exactly one measurement or recorded failure.
- Task/instance/seed averaging and original realization weights define ITT.
- Secure-code yield does not conflate Oracle support, functionality or joint success.
- Bootstrap draws move all descendants of a task together and retain frozen weights.
- Invalid support, unknown coverage or resampling never triggers an unadjusted fallback.
- Context modifiers and robustness/adoption labels require prospectively frozen rules;
  missing rules remain blocked. Tests cannot authorize formal reporting.

## Reading order

1. `docs/protocol.md`: scientific decisions and unresolved activation requirements.
2. `src/prompt_mechanism_study/target_workflow.py`: linear seven-stage entry.
3. `src/prompt_mechanism_study/prompt_contract.py`: source semantic records and compilation.
4. `src/prompt_mechanism_study/candidate_construction.py`: Atomic factors and scope binding.
5. `src/prompt_mechanism_study/prioritization.py`: discoverability, shared scores and fixed slots.
6. `src/prompt_mechanism_study/study_design.py`: pre-outcome freezes and budget/assignment checks.
7. `src/prompt_mechanism_study/randomization.py`: deterministic complete-block assignment.
8. `src/prompt_mechanism_study/measurement.py`: independent outcome measurement.
9. `src/prompt_mechanism_study/inference.py`: task-unit ITT and simultaneous family.
10. `src/prompt_mechanism_study/verification/`: independent saved-input/statistical replay.

The [test guide](../tests/README.md) gives focused commands. Historical attempts,
provider administration and local caches are outside the default reviewer path.
Frozen Pair outputs retain their original interpretation on the preserved branch;
main's smaller mutable smoke fixture is not a revision of those results.
