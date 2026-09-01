# Parameter Qualification Register

**Status:** `NON_NORMATIVE_PHASE_0_REGISTER`

**Normative target:**
[`../specs/2026-08-20-context-conditioned-intervention-policy-framework.md`](../specs/2026-08-20-context-conditioned-intervention-policy-framework.md)

This register separates values observed in current code from values qualified for the target method.
No current default below is automatically transferable. A target value may enter a formal config
only after its candidate profile is developed on `QUAL_DEV`, its complete plan is frozen, it passes
the one-shot unexposed `QUAL_ACCEPT`, and its accepted artifact is referenced by the active protocol.

## Status vocabulary

| Status | Meaning |
|---|---|
| `PROPOSED` | Field and qualification route are specified, but no accepted value exists. |
| `DECISION_RECORDED` | Author-approved semantics and focused code/tests exist, but no formal frozen study artifact or active-path cutover exists. |
| `AUTHOR_INPUT_NEEDED` | A scientific or budget choice cannot be inferred from code. |
| `QUALIFICATION_READY` | Data, procedure, acceptance rule, and output schema are ready to execute. |
| `FROZEN` | An immutable qualification artifact was accepted and is cited by the protocol. |
| `BLOCKED` | A prerequisite decision, data role, or executable qualification procedure is missing. |

No entry in this Phase 0 register is `FROZEN`.

## Required qualification artifacts

| Artifact | Required content | Must not use | Unlocks |
|---|---|---|---|
| `qualification_data_manifest.json` | Protocol ID; task-unit IDs; `QUAL_DEV`/one-shot `QUAL_ACCEPT`/`DISCOVERY`/`CONFIRMATION`/`LEGACY_ONLY` role; source lineage; near-duplicate group; exposure history; assignment version; digests; disjointness report | Discovery outcomes, confirmation assignments, confirmation outcomes, or any exposed acceptance set relabelled as fresh | All parameter qualification |
| `identity_and_scope_decision.json` | Canonical scope fields/serialization; model effect coordinate; model-invariant policy-key decision; examples and collision tests | Outcome results | Candidate schemas, bridge, model dispatch |
| `qualification_plan_bundle.json` | All six candidate/selected profiles, including the RQ1 baseline-set profile; selection rules; metrics; thresholds; tie-breaks; failure behavior; one code commit; one acceptance data ID | Acceptance observations before the plan is frozen; second-profile fallback or acceptance retry | One-shot integrated acceptance |
| `fci_profile_qualification.json` | Complete backend/encoding/CI/BK/bootstrap profile; validity rates; stability curves; acceptance decision | Discovery or confirmation outcomes used after tuning | Atomic FCI Gate |
| `rd_profile_qualification.json` | Atomic model, covariates, preprocessing, regularization, fold construction, support thresholds, bootstrap/tie-break; failure simulations | Confirmation outcomes | Atomic Full/RD-only ranking |
| `pair_feasibility_matrix.json` | Compatibility rules and counts by four cells, scope, model, lineage, language, archetype, API | Pair interaction outcomes used to alter eligibility | Pair common universe and `K_I` feasibility |
| `relation_qualification.json` | Control-binding schema; four predicate algorithms; labelled qualification examples; resolution/support metrics; accepted thresholds | Discovery outcome when defining semantic relation truth | Pair Full relation Gate |
| `pair_rd_profile_qualification.json` | Pair covariates, folds, regularization, minimum four-cell support, bootstrap, failure rules, tie-break | Confirmation outcomes | Shared Pair RD ranking |
| `power_and_margin_memo.json` | Atomic/pair practical margins, alpha, multiplicity families, bootstrap validity, task/block counts, power/sensitivity | Observed confirmation effects from the target study | Stage III freeze and five statuses |
| `rq1_baseline_qualification.json` | Selected Core/+Expert/+Random envelope; every selected selector/model coordinate; blinded Expert card or seeded Random plan; target fixed-slot result; independent replay reference; acceptance data and code commit | Target discovery/confirmation outcomes, best-of-many random seeds, or unrecorded expert information | Inclusion of optional baselines in the RQ1 budget and discovery freeze |
| `rq1_budget_qualification.json` | Approved variants, models, `K_A`, `K_I`, tasks, realizations, total block slots, per-service call ceilings, cost assumptions | Outcome-driven removal or replacement | Formal selection/confirmation preflight |
| `discovery_design_freeze.json` | Role/profile/identity references; universe/support/fold/selector rules; `K`; baselines; models; budget; discovery outcome contract | Formal discovery outcomes, selected slots, or confirmation artifacts | Formal discovery execution |
| `confirmation_freeze.json` | Fixed slots; union/fan-out; combined bridge/protocolization dispatch; eligible tasks; realization allocation; model-bound assignments; independently replayed budget preflight; outcomes/estimands/multiplicity/reporting contracts | Confirmation outcomes | Formal randomized confirmation |
| `study_freeze_index.json` | IDs and SHA-256 digests of the two correctly timed freezes | Copied freeze contents or altered timing semantics | Reviewer lookup and exact lineage |
| `formal_report_authorization.json` | Study-freeze index, executed shared evidence, fixed-slot Yield result, evidence ledger, exact environment/command/provider-call references, and independent freeze/evidence verification digests | Test/demo/calibration evidence, non-CONFIRMATION tasks, or unauthorised executed results | Claim-bearing RQ tables only |

## Decision and parameter entries

### Data, identity, and scope

| ID | Target field or decision | Current observed behavior (`preexisting_artifact`, HEAD snapshot) | Qualification/decision procedure | Acceptance evidence | Status |
|---|---|---|---|---|---|
| DATA-01 | Five roles: `QUAL_DEV`, one-shot `QUAL_ACCEPT`, `DISCOVERY`, `CONFIRMATION`, `LEGACY_ONLY` | Foundation records exposure/source/group provenance and rejects task/near-duplicate cross-role overlap; active runners still use legacy splits | Build a newly unexposed acceptance set, freeze the actual role manifest, and require the shared preflight in every formal runner | Empty acceptance exposure history; zero unauthorized overlaps; exact source/digest provenance | `DECISION_RECORDED` |
| DATA-02 | Qualification population coverage | No target role manifest or fresh acceptance population exists; existing v4 and named v5 artifacts are exposed | Census task units by scope, model, state/cell, lineage, language, archetype, and API without opening the new acceptance labels | Every parameter's required support is present without discovery/confirmation reuse | `BLOCKED` |
| ID-01 | Atomic semantic-key fields | Approved target key contains canonical scope, one feature-operation coordinate, and outcome; no expected direction or model | Integrate `AtomicPolicyKey` into target universe/bridge artifacts | Direction cannot change key; outcome/scope/operation changes do | `DECISION_RECORDED` |
| ID-02 | Pair semantic-key fields and factor order | Approved target key contains canonical scope, two canonically sorted feature-operation coordinates, and outcome; no relation/compatibility/model | Integrate `PairPolicyKey` into target pair registry/freeze | Swapping input order cannot create a second pair; relation change cannot change key | `DECISION_RECORDED` |
| ID-03 | Canonical `analysis_scope` | Approved fields are security pattern, context query, and non-empty sorted language/API/task-archetype scopes | Complete current-data scope census and emit exact scope records | Byte-stable canonical examples plus distinct-scope counterexamples | `DECISION_RECORDED` |
| ID-04 | Model-specific effect coordinate and model-invariant `policy_key` | Approved effect is `(policy_key,model_id)`; Stage-II records bind one discovery model and confirmation cannot cross all models again | Integrate model-bound dispatch and explicit policy-lineage deduplication | No bridge duplication and no accidental model-square randomization | `DECISION_RECORDED` |

### Atomic support, folds, RD, and FCI

| ID | Target field or decision | Current observed behavior (`preexisting_artifact`, HEAD snapshot) | Qualification procedure | Acceptance evidence | Status |
|---|---|---|---|---|---|
| A-SUP-01 | Minimum target/baseline task units | Active selector evidence defaults to 2 positive and 2 negative; standalone positivity CLI defaults to 30 per state | Qualification support/power sweep under candidate-specific folds | Accepted threshold supports every fold and stable RD estimation | `BLOCKED` |
| A-SUP-02 | Minimum shared source lineages | Active selector evidence defaults to 1; standalone positivity CLI defaults to 2 | Sensitivity by lineage overlap and hold-one-lineage-out diagnostic | Threshold and failure semantics frozen | `BLOCKED` |
| A-SUP-03 | Resolved state policy | Current active path admits context `PRESENT` and feature `PRESENT/ABSENT`; unresolved/not-applicable fail before scoring | Verify extractor resolution on qualification examples and freeze state handling | Recomputed states and typed failures match independent labels | `PROPOSED` |
| A-FOLD-01 | Number of Atomic folds | Current ridge predictor requires at least 2 but is not the target scorer | Sweep feasible state-stratified fold counts using qualification support only | Every candidate/fold has train/test support or a deterministic non-evaluable record | `BLOCKED` |
| A-FOLD-02 | Fold seed and algorithm | Current prediction hashes task-unit ID; no candidate fold artifact | Define outcome-blind candidate/state-stratified deterministic algorithm and seed domain | Replay is byte-identical; Full/RD-only manifests are identical | `PROPOSED` |
| A-RD-01 | Atomic outcome model and link | Current association uses exact-stratum standardized RD; prediction uses ridge logit loss gain | Compare prespecified candidate models on qualification stability/calibration without target confirmation outcomes | One model computes target-minus-baseline probability-scale RD with no fallback | `BLOCKED` |
| A-RD-02 | Atomic covariates and preprocessing | Current FCI/prediction covariates are plan-configured; categorical FCI inputs are ordinal-coded | Freeze allowed pre-prompt covariates, training-only encoding/scaling, missing policy | Leakage tests and unseen-level fixtures pass | `BLOCKED` |
| A-RD-03 | Atomic regularization | Current ridge value is config-required, not globally frozen | Qualification grid selected by prespecified outcome-blind or nested rule | Value/rule and tie handling are frozen; no discovery-result tuning | `BLOCKED` |
| A-RD-04 | Atomic ranking statistic | Current association multiplies by expected direction | Freeze absolute cross-fitted first-order RD and deterministic tie-break | Negative and positive equal-magnitude fixtures rank as specified without direction metadata | `PROPOSED` |
| A-RD-05 | Atomic rank-stability bootstrap | No target Atomic RD bootstrap profile exists | Task-unit bootstrap on qualification examples; select draws/seed/summary and validity rule | Monte Carlo error and non-evaluable boundary satisfy frozen tolerance | `BLOCKED` |
| A-FCI-01 | Backend/version and stable semantics | `causal-learn==0.1.4.7`; current call uses FCI with pinned capability checks | Reproduce qualified fixtures in a clean supported environment; explicitly confirm stable/order behavior | Backend digest/version and order-permutation checks frozen | `BLOCKED` |
| A-FCI-02 | CI test | Current backend uses G-square | Compare only prespecified tests compatible with mixed/discrete encoded data; document assumptions | Qualified rejection/error behavior and chosen test recorded | `BLOCKED` |
| A-FCI-03 | Encoding/missing policy | Current covariates are ordinal-coded from sorted unique values; X/Y are binary; missing policy partly upstream | Qualify encoding alternatives and missing/unresolved behavior | Encoding is scientifically defensible and independently replayable | `BLOCKED` |
| A-FCI-04 | Alpha | Current default is `0.05` | Prespecified qualification sensitivity grid; no target discovery outcome peeking after freeze | Stability/support trade-off and final value recorded | `BLOCKED` |
| A-FCI-05 | Depth and maximum path length | Current defaults are `-1` and `-1` | Runtime/stability sweep on qualification population | Accepted limits meet stability and budget constraints | `BLOCKED` |
| A-FCI-06 | Bootstrap draws and seed | Current default is 100; deterministic seed derives from plan/family | Estimate Monte Carlo stability and failure rates at prespecified draw counts | Draw count/seed derivation and reproducibility tolerance frozen | `BLOCKED` |
| A-FCI-07 | Valid-draw denominator and minimum fraction | Current score divides adjacency count by configured draws; only all-failed aborts | Simulate backend/CI failures and evaluate candidate/family validity rates | Score divides by valid draws; minimum fraction yields explicit `NON_EVALUABLE` | `PROPOSED` |
| A-FCI-08 | Adjacency threshold | Current FCI is ranked continuously as its own selector; no target hard threshold | Qualification stability curve and feasibility/power trade-off, frozen before discovery | One threshold plus exact boundary behavior recorded | `BLOCKED` |
| A-FCI-09 | Background knowledge | Active v2 requires temporal, domain-removal, and wrong-plausible audits | Re-run typed BK sensitivities on qualification population and freeze allowed/forbidden tier rules | BK digest and sensitivity decision accepted | `QUALIFICATION_READY` once DATA-01 closes |

### Pair compatibility, relations, and second-order RD

| ID | Target field or decision | Current observed behavior (`preexisting_artifact`, HEAD snapshot) | Qualification procedure | Acceptance evidence | Status |
|---|---|---|---|---|---|
| P-COMP-01 | Factorial compatibility rule | Current compatibility is embedded in relation specs and evaluated after relation matching | Define independent operation/target/surface interference rules; label qualification examples | Relationless-compatible and relation-supported-incompatible fixtures behave correctly | `BLOCKED` |
| P-SUP-01 | Minimum task units per four-cell state | Current plan requires a positive configurable value and at least the fold count; no active target value | Pair feasibility/power sweep by scope/model/cell | Every candidate/fold has four-cell support or deterministic failure | `BLOCKED` |
| P-SUP-02 | Shared lineage/language/archetype/API support | Current Gate checks all four and requires configured shared lineages | Evaluate coverage and instability under held-out groups | Exact target fields, thresholds, and typed failures frozen | `BLOCKED` |
| P-SUP-03 | Minimum feature reliability | Current plan has configurable `[0,1]` threshold | Calibrate extractor reliability on qualification labels | Threshold, estimator, confidence rule, and provenance frozen | `BLOCKED` |
| P-BIND-01 | Control-binding/path schema | Target shadow code now content-addresses feature/task/Prompt-TSG bindings, source/sink/surface/control nodes, canonical paths, and alternative groups, and replays ordered edges | Annotate/verify qualification examples and independently recompute the accepted binding profile | Required fields, unresolved cases, and tamper behavior accepted | `BLOCKED` |
| P-REL-01 | Four neutral relation predicates | Target shadow code implements `SAME_FLOW`, `SHARED_SINK`, `DISTINCT_CONTROL_POINTS`, and `ALTERNATIVE_CONTROLS` over frozen bindings | Blind label audit on the prospectively assigned qualification roles | Precision/recall or exact-rule acceptance thresholds and error inventory frozen | `BLOCKED` |
| P-REL-02 | Multiple-match and unresolved policy | Target predicates return typed `UNRESOLVED` for missing/multiple bindings or unresolved graph semantics; relation evidence is attached only after the compatibility-first universe | Qualify deterministic aggregation and unresolved semantics | Full Gate is reproducible; No-Relation universe remains unchanged | `BLOCKED` |
| P-REL-03 | Candidate-level relation support/resolution thresholds | Pair shadow tracks resolved count, present count, present rate among resolved rows, and unresolved fraction without filtering the RD population | Aggregate over all evaluable compatible rows; sweep prespecified thresholds | Changing relation status cannot change pair rows/folds/RD | `BLOCKED` |
| P-FOLD-01 | Pair fold count, seed, and artifact | Current pair scorer deterministically cell-stratifies in memory; plan requires at least 2 folds | Freeze candidate/cell-stratified algorithm and serialize manifest | Full/No-Relation fold manifests are byte-identical | `PROPOSED` |
| P-RD-01 | Pair model, covariates, and regularization | Current ridge-logit computes probability-scale additive interaction; parameters are config fields | Qualify covariates, training-only preprocessing, ridge rule, and model failure | Shared scorer recovers signed hand fixtures and never falls back silently | `BLOCKED` |
| P-RD-02 | Pair bootstrap draws/seed/stability summary | Current plan requires at least 10 draws and records sign stability/median absolute RD | Monte Carlo and feasibility sweep on qualification data | Draw count, seed, summary, validity, and tie-break frozen | `BLOCKED` |

### Confirmation inference, reporting, and budget

| ID | Target field or decision | Current observed behavior (`preexisting_artifact`, HEAD snapshot) | Qualification/decision procedure | Acceptance evidence | Status |
|---|---|---|---|---|---|
| INF-01 | Atomic practical margin | Current selector confirmation uses oriented interval > 0; no target margin | Prospective domain/power justification on qualification/pilot information only | One signed-symmetric magnitude `epsilon_A` and rationale frozen | `AUTHOR_INPUT_NEEDED` |
| INF-02 | Pair practical margin | Current factorial plan supports a configurable margin; historical values are not transferable | Prospective domain/power justification independent of target outcomes | One `epsilon_I` and rationale frozen | `AUTHOR_INPUT_NEEDED` |
| INF-03 | Alpha and simultaneous families | Target inference and power code now use separate two-sided Atomic/Pair unique-coordinate max-\|T\| families and bind their worst-case sizes to the selected budget envelope | Run the frozen assumption grid over qualified union/task sizes | Two-sided family definitions and alpha frozen before randomization | `BLOCKED` |
| INF-04 | Bootstrap draws, seed, quantile, valid fraction | `PowerAndMarginMemo` is now the sole source of target bootstrap draws/seed/`higher` quantile/valid fraction, and cannot authorize inference while blocked | Monte Carlo error and degeneracy simulation at proposed union/task sizes | Exact profiles and non-evaluable rule frozen | `BLOCKED` |
| INF-05 | Five-level status boundaries | Target enum/classifier and independent verifier implement positive, negative, practical-null, inconclusive, and non-evaluable with exact inclusive/exclusive boundaries | Hand-calculated interval boundary table for both orders | Independent verifier reproduces all five statuses exactly | `DECISION_RECORDED` |
| INF-06 | RQ2 descriptive yield rule | Target shared evidence fans one unique status to every fixed slot; empty/failure/non-evaluable slots contribute zero and no rank pairing or nested utility interval is used | Freeze fixed-slot, unique-result fan-out, zero contribution of empty/failure/non-evaluable slots | Hand ledger reproduces Full-minus-Ablation without rank pairing | `DECISION_RECORDED` |
| BUD-01 | RQ1 comparison and baseline set | Target Core and both-track blinded Expert/seeded Random selectors are implemented and tested. Expert sees only the frozen semantic/support card fields; Random uses one frozen SHA-256 seed; both emit ordinary fixed-slot sources and independently replay. The integrated qualification now has a sixth baseline-set profile, and the budget requires an accepted contract for every selected selector/model coordinate. Legacy Association/Prediction remain old-schema only. | Author freezes the exact RQ1 claim and one Core/+Expert/+Random envelope before outcomes, supplies the actual Expert cards or Random seeds, and runs the one-shot integrated baseline qualification. Association/Prediction require a separately approved target contract if selected. | Core sole-difference and baseline blindness/seed/permutation/shared-union tests pass; missing-coordinate, budget-only, or legacy-only baselines cannot authorize the budget or `DiscoveryDesignFreeze` | `IMPLEMENTATION_TESTED_BASELINE_SET_AUTHOR_AND_QUALIFICATION_BLOCKED` |
| BUD-02 | `K_A` and `K_I` | The joint Gate now derives max-\|T\| family size and worst-case calls from `K_A/K_I`; values still have no author-approved qualification | Joint feasibility, power, and worst-case call budget qualification | Values fit support and approved cap; empty slots remain denominators | `BLOCKED` |
| BUD-03 | Models, tasks, realizations, and total block slots | The author selected Beijing `qwen3.7-flash-2026-07-15` as the sole fixed snapshot for every prospective external LLM role, with no dynamic alias, fallback, or replication model. Model-bound dispatch, one realization per task-policy coordinate, exact four-arm/cell slots, and actual-assignment replay are implemented; task, realization, and slot values remain unset | Qualify the fixed snapshot separately for every assigned role, freeze exact coordinates and minimum tasks per realization/stratum, and verify the smallest representative run first | One numeric request table with no hidden model, fallback, retry, or realization cross-product | `AUTHOR_MODEL_SELECTED_REMAINING_INPUT_AND_QUALIFICATION_BLOCKED` |
| BUD-04 | Provider/request and cost ceilings | The author selected Alibaba Bailian pay-as-you-go, Beijing, CNY, and the fixed Flash snapshot for all three formal call classes. Candidate list-price/token ceilings now replay to CNY 0.004916 materialization, 0.004096 generation, and 0.002458 functional-judge maxima per call. `ProviderBudgetCeilings` rejects hidden retries, tier overflow, or cost mismatch; the total monetary cap is not approved | Recheck and freeze the service price reference and conservative token caps with the selected joint design, then approve one total-cost ceiling | Independent replay rejects tier overflow, cost mismatch, mixed currencies, hidden retry, or any reservation above a call/cost ceiling | `IMPLEMENTATION_TESTED_PROVIDER_SELECTED_TOTAL_CAP_BLOCKED` |

## Single author decision gate

The method implementation is ready for prospective qualification, but qualification and provider
execution must remain disabled until the following block is approved as one joint decision. This
block is a response template, not a frozen configuration or authorization artifact. In particular,
`240` is a prospective coverage target across `QUAL_DEV`, one-shot `QUAL_ACCEPT`, `DISCOVERY`, and
`CONFIRMATION`; it excludes `LEGACY_ONLY` and does not replace hypothesis-specific power analysis.
The current outcome-blind census contains 141 unexposed ready task units.

The completed all-task review now supplies a separately frozen upstream source
population: 381 `QUALITY_INCLUDED` Python task units from reviewer bundle
`33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`,
with sorted task-unit ID-set digest
`d172831733911a29bfe4755adec05b86490d7e72873d5f03bca30d0ad5a819e8`.
This closes data quality and source-population identity only. It does not
approve the 101-task technical-readiness diagnostic subset, allocate roles,
open `QUAL_ACCEPT`, or resolve any author decision below.

The complete outcome-blind ledger contains 346 quality-qualified Python task units in the current
21-CWE scope. After 28 exact legacy overlaps, its exact-unexposed ceiling is 318: 141 ready, 159
pending Oracle support, 16 pending binding, and two pending independent review. Thus the 240 total
can be reached without changing the CWE scope if enough missing measurement profiles qualify. The
four equal 60-task family targets remain the hard data shortfall: the exact-unexposed ceilings are
128 injection/interpreter, 91 file/parser/resource, 43 identity/authorization/permission, and 56
cryptography/randomness/integrity. Retaining 60/60/60/60 therefore requires at least 17 genuinely
new identity-family and four genuinely new cryptography-family task units, plus reserve for any
later near-duplicate exclusions.

```yaml
author_decision_status: PARTIALLY_DECIDED_PROVIDER_MODEL_ONLY

# Choose exactly one. The second option may use fewer than 240 only when the
# prospectively frozen power and role-disjointness Gates pass; otherwise new
# unexposed task units must be acquired.
population_strategy: >-
  retain_240_and_expand
  | allow_power_qualified_shortfall_amendment

# Choose exactly one. Expanding to the priority-extension CWEs changes the
# target population and must occur before role assignment or outcome access.
population_scope_strategy: >-
  preserve_current_21_cwe_scope_and_acquire_new_tasks
  | prospectively_expand_to_priority_extension_cwes

# Signed-symmetric practical risk-difference margins on oracle-evaluable
# secure-code yield. These are scientific values, not software defaults.
atomic_practical_margin: UNDECIDED
pair_practical_margin: UNDECIDED

# Choose exactly one. Core always contains Atomic Full/RD-only plus Pair
# Full/No-Relation. Selecting an external baseline makes its target-schema
# implementation and qualification mandatory before DiscoveryDesignFreeze.
rq1_scenario: core | core_plus_expert | core_plus_expert_plus_random

# If a statistical external comparator is required, list it explicitly rather
# than silently reusing the legacy association/prediction selector. Its Atomic
# and Pair definitions must be qualified and shown not to duplicate the Core
# ablations. Empty means none.
additional_statistical_baselines: []

# Author-selected exact provider coordinate for every prospective external LLM
# call. Role-specific qualification is still mandatory; in particular, the old
# Qwen3.7-Max judge result does not qualify the new Flash judge.
prospective_llm_snapshot: qwen3.7-flash-2026-07-15
primary_generation_models: [qwen3.7-flash-2026-07-15]
replication_models: []
dynamic_model_alias_allowed: false
fallback_models: []

# These are qualification ceilings, not guaranteed selected values. The final
# K and task counts are the largest prospectively allowed combination that
# passes support, max-|T| power, population, and cost Gates.
atomic_top_k_ceiling: UNDECIDED
pair_top_k_ceiling: UNDECIDED
familywise_alpha: UNDECIDED
minimum_target_power: UNDECIDED

# One task-policy coordinate always receives exactly one realization and one
# complete four-arm block. Any additional request slots must be explicit here.
atomic_global_realization_count: UNDECIDED
pair_global_realization_count: UNDECIDED
request_slots_per_task_arm: UNDECIDED

# A monetary cap alone is insufficient: after model selection, all three call
# kinds require frozen price references and conservative per-call microunit
# bounds. Automatic retry ceiling remains zero.
budget_currency: CNY
maximum_total_external_cost: UNDECIDED
provider_deployment_region: cn-beijing
materialization_provider: ali_bailian_pay_as_you_go
generation_provider: ali_bailian_pay_as_you_go
functional_judge_provider: ali_bailian_pay_as_you_go
automatic_retry_ceiling: 0
```

The current evidence-based starting recommendation, still non-authorizing, is:
`retain_240_and_expand`, preserve the current 21-CWE scope, practical margins 0.05/0.05, Core RQ1,
the author-selected fixed `qwen3.7-flash-2026-07-15` snapshot for all external LLM roles with no
replication or fallback model, `K_A <= 5`, `K_I <= 3`, alpha 0.05, minimum power 0.80, two global
realizations, and two request slots per arm. A CNY 100 cap is recommended for the initial
exploratory study and CNY 1,000 for the full formal envelope; the applicable cap still requires
explicit author approval. Flash must pass each role-specific qualification, including a fresh,
role-disjoint functional-judge `QUAL_ACCEPT`, before formal use.
This replaces the earlier 10/5 and one-slot planning suggestion because the implemented
outcome-blind sensitivity calculation shows materially weaker Pair power and a much larger call
envelope. See `rq1_worst_case_budget.md` under “Outcome-blind author-decision sensitivity.” The
author must still approve this package and supply a total monetary cap before any value can be
frozen.

After approval, the permitted sequence is mechanical: freeze the candidate assumption/profile
grid; power-qualify role counts without target outcomes; either expand the population or seal one
disjoint role manifest; develop on `QUAL_DEV`; freeze the integrated qualification plan; consume
`QUAL_ACCEPT` exactly once; and only then create the discovery-design freeze. No field above may be
changed in response to discovery or confirmation outcomes.

## Current values that must not be copied forward silently

The following are verified descriptions of current code, not target recommendations:

- FCI: causal-learn `0.1.4.7`, G-square, alpha `0.05`, depth `-1`, maximum path
  length `-1`, and 100 bootstrap draws.
- Active Atomic selector support defaults: 2 target-state task units, 2 baseline-state task units,
  and 1 shared source lineage.
- Standalone positivity CLI defaults: 30 task units per state and 2 shared source lineages.
- Atomic ridge regularization/folds, Pair ridge/folds/support/bootstrap, selector `K`, experiment models,
  realizations, and block slots are supplied by run configuration rather than one target profile.
- Inference minimum valid-bootstrap fraction defaults to `0.9`; this does not qualify the same value
  for FCI or RD ranking.
- Zero practical margin and any historical non-zero margins are legacy/configuration facts, not a
  prospective target choice.

## Freeze rule

An entry may move to `FROZEN` only when the repository contains:

1. the immutable qualification-data manifest and role-disjointness proof;
2. the exact qualification command/environment/config and output bundle;
3. the prespecified acceptance rule and observed result;
4. an independent verifier or hand-recomputed fixture where appropriate;
5. the protocol clause citing the artifact ID; and
6. a traceability row connecting the value to implementation, tests, and report fields.
