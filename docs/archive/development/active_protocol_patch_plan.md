# Active Protocol Section-by-Section Patch Plan

**Status:** `NON_NORMATIVE_PHASE_0_PATCH_BLUEPRINT`

**Only normative target:**
[`../specs/2026-08-20-context-conditioned-intervention-policy-framework.md`](../specs/2026-08-20-context-conditioned-intervention-policy-framework.md)

This file is not a successor protocol and must never be cited as method authority. It records the
ordered edits needed to patch the existing normative document into the single executable successor
protocol. The normative header now says `SPECIFIED_DRAFT` and must retain that status while the
target migration is unfinished. Identity, data-role, and budget-envelope semantics were approved and
patched on 2026-08-31; no numeric qualification value is frozen merely because it appears here.

## Patch policy

1. Patch the existing protocol in place; do not create another normative specification.
2. Preserve the seven paper-facing stages: representation, prioritization, hypothesis freeze,
   intervention/randomization, measurement, outcome assembly, and inference/reporting.
3. Freeze identity and data-role semantics before selector mathematics, and selector mathematics
   before result schemas or paper prose.
4. A parameter becomes normative only after its named qualification artifact is frozen and cited by
   the protocol.
5. Existing schema-2.1 selector, schema-2.0 successor, and schema-1.2 interaction artifacts retain
   their historical interpretation. They are never relabelled as target-protocol evidence.
6. Scope contraction removes only unapproved algorithms. Atomic Full/RD-only and Pair
   Full/No-Relation are mandatory comparisons. Every external baseline selected for RQ1 must be
   implemented, qualified, budgeted, frozen, and independently verified in the target schema; a
   symbolic budget name or a legacy selector implementation is not sufficient.

## RQ1 comparison implementation policy

The fast path distinguishes three categories instead of imposing a blanket ban on new comparison
code:

1. **Required component comparisons:** Atomic Full versus RD-only and Pair Full versus No-Relation.
   These four selectors are always in scope and already have target implementation tests.
2. **Author-selected external baselines:** blinded Expert, seeded Random, or a separately defined
   Association/Prediction comparator. Once selected, each is required method work and must use the
   same frozen universe, fixed `K`, bridge, confirmation protocol, status vocabulary, evidence
   fan-out, and budget accounting as the primary selectors.
3. **Unapproved exploratory algorithms:** PC/RFCI/GFCI/JCI or any other selector not named in the
   frozen RQ1 set. These remain out of the active path unless separately qualified before outcomes.

Core-only execution is allowed only with a correspondingly narrow RQ1 claim about fixed-budget
PHASE yield and component contribution. Any claim comparing PHASE with an independent method
requires at least one frozen external baseline. Association/Prediction cannot be copied from the
legacy five-selector suite without defining their target Atomic/Pair scope and proving that they are
not duplicates of RD-only/No-Relation. Expert and Random budget identities likewise do not count as
implementations until their selector artifacts and verifier paths exist.

## Section-by-section patch map

| Existing location | Required patch | Inputs that must exist first | Exit condition |
|---|---|---|---|
| Front matter | **Foundation patch complete:** header now declares `SPECIFIED_DRAFT`, protocol ID, schema family, revision date, and non-executable status. Retain it until all qualification references, active-path integration, and acceptance checks close. | Remaining qualification register and cutover work | One header uniquely identifies the target protocol without declaring unfinished values frozen. |
| §1 Authority and Supersession | Preserve this file as the sole authority. State that Phase 0 audits are descriptive only; identify old selector/successor/interaction schemas as `LEGACY_ONLY` for target reports while retaining their dedicated verifiers. | Legacy cutover map | No other document can override identity, denominator, estimand, or selector definitions. |
| §2 Scientific Positioning | Replace “FCI is one selector” with Atomic Full = structural admissibility Gate plus shared first-order RD ranking. Define Pair Full = relation Gate plus shared second-order RD ranking. State that discovery prioritizes scarce confirmation capacity and does not identify effects. | FCI/RD and relation decisions | Positioning agrees with the executable Full/Ablation contrasts and makes no directional causal-discovery claim. |
| §3 Non-Negotiable Boundaries | Add direction-neutral identity and inference; `QUAL_DEV`, one-shot `QUAL_ACCEPT`, `DISCOVERY`, `CONFIRMATION`, and `LEGACY_ONLY`; common-universe and sole-difference rules; fixed-slot/no-replacement denominators; unique-confirmation reuse; model-policy dispatch rule. Retain Prompt TSG/causal-structure separation, generated-code boundary, assigned-arm task-unit ITT, and outcome separation. | `D-ID-01`, `D-ID-02`, data-role design | Every invariant has a later artifact and test coordinate. |
| §4 Data-Generating Regimes | Retain discovery and randomized confirmation as the two scientific regimes while separating repeatable qualification development from one-shot acceptance. Add an immutable role manifest, exposure history, near-duplicate firewall, and shared pre-outcome preflight. Rewrite the bridge around semantic key, protocol record ID, and model-invariant policy key. | Qualification data manifest; model-policy decision | No runner can consume a task unit from an unauthorized role or cross a role boundary implicitly. |
| §5 Prompt TSG | Retain typed, non-causal graph semantics. Add the minimum provenance-bound control-binding contract needed to evaluate target pair relations: controlled feature, source/surface role, canonical target or sink, typed path/stage evidence, and unresolved semantics. Do not turn TSG edges into causal edges. | Representation and relation qualification | Every relation predicate can be recomputed from frozen TSG evidence without a free-text judgment. |
| §6 Context-Conditioned Hypotheses | Define canonical Atomic and Pair semantic keys and separate protocol record IDs. Remove `expected_direction`, relation result, compatibility result, lane, rank, score, and qualification status from semantic identity. Retain explicit outcome and canonical `analysis_scope`; resolve whether `model_id` is part of the effect coordinate and whether a separate policy key is required. | `ID-01` through `ID-04`; scope census | Opposite forecast directions and selector memberships map to the same scientific candidate, while scientifically distinct outcome/scope/model coordinates do not collide. |
| §7.1 Variable discipline | Freeze the common Atomic discovery population, allowed pre-prompt covariates, missing/unresolved treatment, task-unit aggregation, and prohibited post-outcome variables. Point to a qualified RD profile and FCI profile. | Data-role, support, RD, FCI qualification | Full and RD-only consume byte-identical candidate rows and candidate-specific folds. |
| §7.2 FCI backend and assumptions | Freeze FCI-Stable semantics, backend/version, CI test, encoding, alpha, depth/path limits, bootstrap count/seed, valid-draw rule, minimum valid fraction, typed background knowledge, and software digest. Define only outcome adjacency as local structural relevance. | `fci_profile_qualification` | FCI returns `PASS`, `FAIL`, or `NON_EVALUABLE`; failures never count as non-adjacency and no possible-cause claim is implied. |
| §7.3 Candidate relations | Replace the current adjacency/possible-ancestry menu with the single qualified adjacency predicate for Atomic Full. Move pair semantic relations to §24. | FCI qualification | Exactly one executable predicate exists in the active atomic path. |
| §7.4–§7.5 Randomness and BK | Align bootstrap randomness with frozen task-unit seeds and valid draws. Preserve the background-knowledge sensitivity audit as qualification/diagnostic evidence, not a second selector. | FCI profile | Replay reproduces folds, bootstrap samples, Gate states, and failure accounting. |
| §8.1 Formal objective | Define fixed-denominator `Yield@K` over frozen slots and candidate-to-slots fan-out. Distinguish unique confirmation cost from selector-slot denominator. Require an RQ1 worst-case budget preflight. | `K_A`, `K_I`, baseline set, model set, slot counts | Objective is computable before outcomes and does not reward duplicate selection. |
| §8.2 Selector-only comparison | Make Atomic Full/RD-only and Pair Full/No-Relation mandatory. Implement every author-selected external baseline in the target schema rather than carrying only a budget name or reusing a legacy result. All approved variants share the frozen candidate space, fixed `K`, bridge, confirmation, status, and evidence accounting; only their prospectively defined ranking information may differ. Remove expected-direction orientation and FCI as its own ranking. | Atomic/Pair qualification; exact RQ1 comparison set; baseline contracts; RQ1 budget | Sole-difference tests close the two component contrasts, and every selected external baseline emits fixed slots that independently replay under its frozen blindness/seed contract. |
| §8.3 Representation comparison | Remove direct/direct+context from active RQ2. Preserve any old implementation as archival analysis only; a future representation study requires a separately frozen protocol. | Protocol author approval | No default command or main-paper RQ treats representation comparison as active confirmation evidence. |
| §8.4 Native-system track | Keep only if it maps to the same data roles and evidence levels. Make clear it cannot supply formal selector yield without target-protocol artifacts. | Evidence-level review | Smoke/demo/native outputs cannot be promoted to confirmation evidence. |
| §9 Multi-Realization Policies | Retain one materialized task-realization bundle containing all four Atomic variants or all four Pair cells. Add deduplication at the approved policy key and immutable selector-to-policy lineage. | Model-policy decision | Repeated selector references do not duplicate policy materialization. |
| §10 Randomization and Units | Retain balanced complete blocks and paper-facing `task_unit_id`. Clarify that discovery folds, FCI bootstrap units, confirmation randomization, and inference resampling all operate at task-unit level. Define model dispatch so model-specific selection cannot be cross-producted a second time. | Model-policy decision; budget preflight | Each intended effect coordinate receives exactly one frozen block family and no accidental model-square expansion. |
| §11 Outcomes and Estimands | Preserve prospective primary safety yield separately from code validity, Oracle support, unknown coverage, functionality, and joint success. Keep assigned-arm ITT and unknown bounds. Remove direction-oriented estimands. | None beyond identity freeze | One outcome dictionary and estimator contract serves all selectors without denominator filtering. |
| §12 Multiplicity and Inference | Define one simultaneous family over unique Atomic effect coordinates and one over unique Pair coordinates. Freeze two-sided intervals, practical margins, and five statuses: positive meaningful, negative meaningful, practically null, inconclusive, non-evaluable. Define pair signs as positive/negative interaction, never automatically “synergy/antagonism.” | Power/margin and multiplicity qualification | A unique candidate has one interval/status reused by every selector slot. |
| §13 Robustness | Retain realization/model heterogeneity as secondary robustness. Remove expected-direction pass/fail orientation. State that heterogeneous or adverse effects remain reportable and cannot be hidden by selector summaries. | Identity and inference patch | Robustness fields cannot change primary assigned-arm ITT membership. |
| §14 Optional Markers | Keep fidelity, compliance, generation success, and non-target drift as diagnostics only. Add explicit prohibition on their use as denominator filters or replacement triggers. | None | Diagnostic absence or failure cannot remove an assignment from ITT. |
| §15 Evidence Levels | Replace/augment current labels with explicit `specified`, `implemented`, `tested`, `executed`, and `reported`. Define admissible evidence types and prohibit demo/smoke/calibration promotion. | Traceability contract | Every RQ table cell exposes its highest achieved evidence level and source artifact. |
| §16 Main-Paper RQs | Freeze RQ1 around the approved selector set and budget. Restrict RQ2 to Atomic Full vs RD-only and Pair Full vs No-Relation fixed-`K` descriptive yield. Keep RQ3/RQ4 only for confirmed policy effects/robustness supported by Stage III; remove SOTA and broad component claims not backed by the target design. | Author RQ1 choice; RQ budget; inference qualification | RQ text, result fields, and table builders have a one-to-one map. |
| §17 JCI, RFCI, Expert Scope | Keep JCI/RFCI outside the active method unless prospectively qualified. Require every author-selected Expert/Random or statistical external baseline to have a target-schema ranking contract, fixed blindness/seed provenance, implementation tests, qualification evidence, and budget ID. | Exact RQ1 baseline decision and baseline qualification | Unselected methods cannot appear in active configs; selected baselines cannot be omitted or represented only by scenario names. |
| §18 Artifacts and Provenance | Add semantic-key registry, protocol records, data-role manifest, candidate-specific fold manifests, FCI/RD profiles, compatibility and relation evidence, fixed slot ledgers, `candidate_to_slots`, unique confirmation union, status records, budget preflight, and qualification IDs. Split timing into `DiscoveryDesignFreeze` before discovery outcomes and `ConfirmationFreeze` after slots but before confirmation outcomes; index both without creating a parallel framework. | All schema decisions | Every scientific claim maps to the correctly timed frozen input, config, function, result field, verifier, and table builder. |
| §19 Sample-Size and Data Gate | Separate parameter qualification from discovery and confirmation. Require feasibility/power/margin/RQ1 budget artifacts before formal freeze. Define hard rejection when candidate support, valid FCI fraction, pair four-cell support, relation resolvability, confirmation power, or provider budget is insufficient. | Qualification outputs | No placeholder/default can enter a formal run. |
| §20 Failure and Negative Results | Enumerate typed empty slots, support failure, FCI non-evaluable, RD non-evaluable, bridge failure, protocolization failure, backend failure, unknown outcome, practical null, adverse effect, and multiplicity-inconclusive status. No replacement. | Status schema | All assigned slots remain in `K`; all assignments remain in ITT; adverse/zero/failed results remain reportable. |
| §21 Migration Boundary | Mark old selector/successor/interaction schemas as verifiable legacy. Require explicit active protocol ID and data role at every target report boundary. Remove old commands from default docs/imports without deleting historical readers needed for reproducibility. | Cutover map and compatibility tests | An old artifact verifies historically but is rejected by the target report builder. |
| §22 Acceptance Criteria | Rewrite acceptance around sole-difference contracts, identity replay, role firewall, support/fold replay, valid FCI draws, pair decoupling, slots/union, unique confirmation reuse, assigned-arm ITT, five statuses, independent verification, and one reviewer smoke/full reproduction. | Complete traceability matrix | Every criterion has at least one positive and one tamper/failure test. |
| §23 Conflict-and-Decision Ledger | Add unresolved identity/scope/model-policy, relation schema, thresholds, margins, RQ1 baseline set, `K_A`, `K_I`, task/model/realization set, and budget decisions. Record who decided, qualification artifact, date, and protocol patch. | Author and qualification inputs | No unresolved decision is disguised as an implementation default. |
| §24.1–§24.3 Pair Scope, Identity, Eligibility | Define one compatibility-derived common Pair universe. Pair semantic identity uses context, unordered/canonically ordered factor-operation coordinates, outcome, scope, and model effect coordinate as approved; it excludes relation/eligibility evidence. Relation evaluation occurs after compatibility and cannot change RD rows. | Pair identity and feasibility decisions | A compatible relationless pair is eligible for No-Relation; a relation-supported incompatible pair is eligible for neither. |
| §24.2 Pair Structural Prior | Replace relation-first identity with four executable, neutral Prompt-TSG predicates backed by control bindings and typed provenance. Freeze multiple-match and unresolved behavior. State again that these are semantic priors, not causal graph edges. | Relation qualification | Every predicate has positive, negative, unresolved, multiple-match, and tamper fixtures. |
| §24.3–§24.4 Pair Prioritization and Cells | Compute one candidate-specific cross-fitted probability-scale second-order RD for every compatible pair using all qualified rows/folds. Pair Full filters on aggregated relation support; No-Relation does not. Both use identical score, tie-break, support Gate, and `K_I`. | Pair RD/fold and relation qualification | A shared pair has byte-identical score/folds across variants, with a sole-difference proof. |
| §24.5–§24.10 Pair Confirmation and Reporting | Retain complete `2 x 2` randomization, Oracle support separation, task-unit ITT, unknown bounds, and two-sided interaction intervals. Add fixed Pair slots, union, shared confirmation, five statuses, descriptive yield difference, and target verifier/report requirements. | Identity, inference, budget decisions | Pair RQ2b can be reconstructed from slots plus unique result records without rank-position matching. |
| §24.11 Follow-ups | Keep post-confirmation context analyses exploratory and outside frozen selector yield/multiplicity families. | None | Follow-up outputs cannot alter primary statuses or RQ2 denominators. |

## Ordered patch passes

### Pass A — authority, identities, and firewalls

Patch the front matter and §§1, 3, 4, 6, 18, 21, and 23. This pass must resolve:

- canonical `analysis_scope`;
- model-specific effect coordinate versus model-invariant policy key;
- five data roles, one-shot acceptance, and disjointness;
- semantic-key versus protocol-record serialization;
- active-versus-legacy report boundary.

No selector implementation should start before Pass A is reviewed.

**2026-08-31 progress:** the author decision portion of Pass A is complete. The draft protocol and
focused foundation code now define canonical `AnalysisScope`, model-independent Atomic/Pair
`policy_key`, `(policy_key,model_id)` effects, model-bound candidate records, five data roles, and
task/near-duplicate firewalls. The budget contract also fixes one outcome-blind realization
allocation per task-policy coordinate, so global realization count does not multiply all requests.
The review-approved refinement now separates `QUAL_DEV` from one-shot unexposed `QUAL_ACCEPT` and
separates the discovery-design and confirmation freeze moments. Remaining Pass A work is to build a
fresh acceptance population, emit the actual study manifest, freeze the integrated qualification
plans, require the shared firewall in every target preflight, integrate model-bound
bridge/randomization dispatch, and complete the active-versus-legacy report boundary. Existing v4
and named v5 artifacts are exposed and cannot be relabelled as fresh acceptance. This is not a
formal freeze or selector cutover.

### Pass B — qualified prioritization contracts

Patch §§5, 7, 8, 17, 19, and §§24.1–24.4 only after the qualification register contains
accepted artifact IDs. This pass freezes:

- Atomic support, folds, RD, FCI, Gate, ranks, and slots;
- Pair compatibility, control bindings, relation predicates/aggregation, folds, RD, and slots;
- the executable target-schema implementation and qualification of every selected RQ1 comparison
  method/baseline;
- RQ1 selector set, `K_A`, `K_I`, and worst-case budget.

### Pass C — shared confirmation and inference

Patch §§9–16, 20, and §§24.5–24.11. This pass freezes unique policy reuse, model dispatch,
randomization, outcomes, multiplicity, five statuses, RQ wording, and descriptive yield.

### Pass D — acceptance and cutover

Complete §§18, 21, and 22 after implementation artifacts and independent-verifier tests exist.
Then update the reviewer guide, CLI documentation, and paper from the traceability matrix. The
protocol remains `SPECIFIED_DRAFT` until this pass closes.

## Prohibited intermediate states

- New selector code with old direction-bearing identities.
- Model-specific candidate IDs passed to the current all-model cross-product runner.
- Pair Full constructed from a relation-first universe while No-Relation uses a larger universe.
- Parameter defaults described as frozen without a qualification artifact.
- An RQ1 scenario that names a baseline for budgeting but lacks its executable target selector,
  qualification evidence, fixed-slot artifact, or independent verifier.
- A new CLI declared active while the protocol still describes the old selector suite.
- Paper RQ or result tables updated before the exact result fields and verifier exist.
- Historical artifacts loaded by a target report builder merely because their legacy verifier passes.

## Patch completion gate

The protocol patch is ready for implementation only when:

1. all `AUTHOR_DECISION` items in the gap matrix are closed;
2. every required qualification artifact has a frozen ID and disjoint data-role provenance;
3. the RQ1 worst-case budget fits the approved cap;
4. every comparison method and external baseline in the approved RQ1 set has a target-schema
   implementation, qualification artifact, fixed-slot output, and independent verifier;
5. every target clause has an implementation, artifact, test, verifier, and paper destination in the
   traceability matrix; and
6. an independent reader can identify one—and only one—active path through all seven stages.
