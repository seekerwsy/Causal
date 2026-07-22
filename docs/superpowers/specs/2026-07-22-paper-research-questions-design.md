# FSE 2027 Research Questions and Evaluation Design

**Date:** 2026-07-22

**Status:** Approved design pending written-spec review

**Scope:** Paper-facing research questions, operationalization, evidence levels, and evaluation metrics

## 1. Objective

This design revises the four research questions in
`paper/fse2027/secaware-fse2027-draft.tex` while preserving their original subjects:

1. method-level discovery and confirmation;
2. component contribution;
3. defensive prompt interventions; and
4. human-centered explanation utility.

The revision aligns the paper with the current Prompt-only, TSG-constrained FCI discovery and
randomized held-out confirmation framework. Research-question sentences remain concise. Algorithm,
estimand, metric, and validity details belong in the operationalization paragraphs that follow each
question.

This document does not revise the manuscript or implement new evaluation code. It defines the
paper-facing design that those later changes must follow.

## 2. Causal and Evaluation Boundaries

All four RQs obey these boundaries:

1. Prompt TSG is the only authoritative structured feature representation.
2. Prompt TSG edges encode prompt task/security semantics, not causal edges.
3. Generated code is consumed only by the independent Oracle and the committed functional evaluator.
4. No Code TSG, AST feature, code-side guard/source/sink trace, or code mechanism mediator enters a
   causal table or paper-facing mechanism claim.
5. Discovery uses only the discover split. Randomized confirmation uses held-out confirm tasks.
6. Native hypotheses, mappings, ranks, expected directions, outcomes, and contrasts are frozen before
   confirm outcomes exist.
7. Randomized, task-clustered ITT is the primary confirmatory estimand.
8. Realized `target_changed`, target-semantic compliance, non-target drift, and directional changes are
   diagnostics and never filter the randomized ITT denominator.
9. Hard structural, provenance, security-neutrality, and AllowedDelta failures occur before
   randomization. Valid post-assignment terminal outcomes remain in the assigned arm.
10. JCI is a secondary structural analysis. RFCI is an optional sensitivity analysis. Neither changes
    frozen hypotheses or primary ITT conclusions.
11. Effects are not pooled across hypotheses, target features, operations, models, or CWE scopes
    without a separately approved estimand.
12. Every tested hypothesis and configuration is reported, including null, conflicting, and
    non-evaluable cases. Results may not select a favorable method or configuration post hoc.

## 3. Research Questions

### RQ1: Discovery and Confirmation

> **RQ1. How effectively can different methods discover and confirm security-relevant prompt-side
> mechanisms in LLM code generation?**

RQ1 preserves the original comparison of method-native discovery outputs while defining confirmation
through the shared randomized ITT protocol.

### RQ2: Component Contribution

> **RQ2. How do SecAware's structured representation and causal analysis components contribute to
> mechanism discovery and confirmation?**

RQ2 is a pre-registered component ablation. It does not automatically rank or select a production
backend.

### RQ3: Defensive Interventions

> **RQ3. Which prompt-side defensive interventions effectively reduce insecure code generation?**

RQ3 is a substantive analysis of frozen, target-specific safety-control hypotheses. It does not claim
to enumerate every possible defense.

### RQ4: Perceived Explanation Utility

> **RQ4. How do security experts rate and rank the perceived quality and usefulness of explanations
> produced by different methods?**

RQ4 measures perceived quality and utility. It does not claim that explanations improve objective
mechanism-identification or repair accuracy.

## 4. Shared Discover/Confirm Protocol

Every computational method or ablation receives:

- the same discover and confirm task manifests;
- the same configured models and generation seed slots;
- the same independent Oracle and functional-outcome contracts;
- the same candidate budget by pre-registered model/CWE scope;
- the same family-valid intervention-arm protocol;
- the same randomization, outcome encoding, clustered uncertainty, and multiplicity policy.

Method-native hypotheses are produced and ranked on the discover split. Post-discovery mapping may
translate a native hypothesis into the shared intervention vocabulary, but it may not change the
native claim, inspect confirm outcomes, or choose among targets based on favorable results. Accepted
hypotheses, mappings, expected directions, and ranks are frozen before confirmation variants or
assignments exist.

## 5. RQ1 Operationalization

The RQ1 method set is frozen before the final discover run. It preserves the manuscript's intended
comparison categories: Full SecAware, prompt attribution, causal prompt concepts, prompt
perturbation, and an LLM-judge explanation method. Exact implementations, versions, prompts, and
native output contracts require the later evaluation implementation plan. No external baseline may
read SecAware Prompt TSG features during native discovery. Shared catalog mapping occurs only after
the baseline has committed its native candidate.

### 5.1 Native candidates and fixed budget

For every method and pre-registered scope, let `K` be the candidate-slot budget. Native candidates are
canonicalized and deduplicated before occupying slots. A method without a native ranking must declare
a deterministic ranking and tie-break policy before confirmation.

The method may fill fewer than `K` slots. Empty slots remain failures to produce candidates; they are
not removed from end-to-end yield denominators.

### 5.2 Mapping semantics

Mapping translates one native candidate into, at most, one primary intervention target:

```text
NativeHypothesis
  -> feature_family
  -> catalog-bound feature_id
  -> ADD or REMOVE
  -> model/CWE/task scope
  -> pre-registered outcome
  -> expected direction
```

A mapping is valid only when the native evidence identifies one catalog-bound target and its scope
without changing the native meaning. Generic advice, ambiguous targets, unsupported directions, and
one-to-many candidates are recorded as unmapped. A generic security reminder is a control arm, not a
target-specific mapping.

Expected direction may come only from the frozen method-native claim or from a direction rule already
declared by the immutable feature/operation catalog. Its source is persisted. If neither supplies a
unique direction before confirmation, the candidate is unmapped; the mapper may not infer direction
from confirm outcomes.

The mapping policy, catalog, mapper identity, and any locked model/template configuration are frozen.
The mapper is blind to confirm code, outcomes, arm assignments, and method performance. Method
identity should be hidden during sampled human mapping audits where feasible.

### 5.3 Mapping coverage

Let:

- `N_native` be the number of valid frozen native candidates among the `K` slots;
- `N_mapped` be the number with one valid mapping.

Conditional mapping coverage is:

```text
N_mapped / N_native
```

It measures compatibility between native explanations and the shared finite intervention vocabulary.
It is a bridge diagnostic, not causal precision or hypothesis correctness. When `N_native = 0`, it is
reported as not applicable.

Mapped yield at `K` is:

```text
N_mapped / K
```

Both quantities must be reported. Conditional coverage alone can make a method that emits one easily
mapped candidate appear stronger than a method that produces many usable candidates.

### 5.4 RQ1 metric funnel

The finite end-to-end funnel is:

```text
K candidate slots
  -> N_native frozen native candidates
  -> N_mapped uniquely mapped candidates
  -> N_protocol candidates with a valid intervention protocol
  -> N_randomized candidates entering random assignment
  -> N_confirmed candidates with confirmatory ITT evidence
```

RQ1 reports:

1. **Candidate-slot utilization:** `N_native / K`.
2. **Conditional mapping coverage:** `N_mapped / N_native`.
3. **Mapped yield at K:** `N_mapped / K`.
4. **Hypothesis-level protocolization rate:** `N_protocol / N_mapped`.
5. **Task-instance block-freeze coverage:** complete frozen blocks divided by pre-randomization eligible
   task/hypothesis blocks.
6. **Randomized yield at K:** `N_randomized / K`.
7. **Confirmed yield at K:** `N_confirmed / K`.
8. **Conditional confirmation rate:** `N_confirmed / N_randomized`, reported only as a secondary
   diagnostic.
9. **Hypothesis-specific effects:** target-minus-no-op ITT, task-clustered interval, multiplicity-
   adjusted status, independent-task count, arm counts, and pre-registered secondary contrasts.

Confirmed yield at `K` is the primary method-level RQ1 metric. It is an end-to-end workflow yield, not
a pooled causal effect. Hypothesis-specific ITT effects remain separate.

The exact multiplicity family must be pre-registered over the method-by-rank hypotheses used for the
comparative RQ1 claim. Unfilled slots do not create a smaller, more favorable testing family after
outcomes are observed.

## 6. Primary ITT and Evidence Levels

For a safety ADD protocol, the primary effect is:

```text
mean(Y_secure_functional | assigned TARGET_PATCH)
  - mean(Y_secure_functional | assigned NOOP_REWRITE)
```

Safety REMOVE uses the analogous target-remove minus no-op-retain contrast. All committed assignments
enter the assigned arm denominator. Uncertainty is resampled by task cluster.

Paper-facing evidence levels are:

### 6.1 Observational Candidate

A discover-split stable possible path that passes configured FCI/bootstrap requirements and is frozen
before confirmation. It is not a causal confirmation.

### 6.2 Confirmed Intervention Effect

The pre-registered target-minus-no-op ITT has the frozen expected direction, satisfies the minimum
independent-task requirement, and has a multiplicity-adjusted interval excluding zero. Required
artifacts and provenance must be complete. Realized treatment fidelity is not a filter.

### 6.3 Target-Specific Effect

A Confirmed Intervention Effect additionally supported by the pre-registered direct target-minus-
placebo and, where family-valid, target-minus-generic control contrasts. Failure to reject a generic
arm against no-op does not by itself establish target specificity.

### 6.4 Bidirectional Support

Separate ADD and REMOVE protocols for the same feature independently produce confirmed effects in
opposite expected directions. This is stronger directional evidence, not a claim of causal necessity,
sufficiency, or code-side mediation.

### 6.5 Directionally Consistent but Inconclusive

The ITT point estimate has the expected direction, but its adjusted interval includes zero or support
is insufficient. Diagnostics cannot promote it to confirmation.

### 6.6 Null, Conflicting, and Non-Evaluable

- **Null:** the estimate supplies no detectable effect under the pre-registered analysis.
- **Conflicting:** the ITT direction conflicts with the frozen expectation.
- **Non-evaluable:** the protocol never entered a valid randomization universe or required
  infrastructure/provenance prevents publication.

Valid post-assignment terminal non-successes remain ITT data and do not create non-evaluable rows.

## 7. Directional-Change Diagnostics

The draft's opportunity-conditioned flip rate must not be a primary estimand or confirmation
criterion. Parallel randomized arms identify marginal arm effects, not the individual probability
that one unit changes from insecure to secure under treatment.

For every complete task block `b`, compute target and no-op arm success rates, `Ybar_b,T` and
`Ybar_b,C`. Report:

```text
Task improvement rate = count(Ybar_b,T > Ybar_b,C) / B
Task harm rate        = count(Ybar_b,T < Ybar_b,C) / B
Task tie rate         = count(Ybar_b,T = Ybar_b,C) / B
```

These are task-level descriptive diagnostics over all blocks. They do not filter ITT and do not
identify individual causal flips.

Optional benefit/harm probability bounds may be reported from randomized marginal arm rates:

```text
max(0, p_target - p_control)
  <= P(Y(target)=1, Y(control)=0)
  <= min(p_target, 1-p_control)

max(0, p_control - p_target)
  <= P(Y(target)=0, Y(control)=1)
  <= min(p_control, 1-p_target)
```

No monotonicity assumption is made. The old opportunity-conditioned discordance may appear only as a
clearly labeled exploratory appendix diagnostic with a frozen denominator and pairing rule. It cannot
change evidence status or support an individual-flip claim.

## 8. RQ2 Operationalization

RQ2 uses a pre-registered 2-by-2 ablation:

| Configuration | Prompt representation | Hypothesis selection |
| --- | --- | --- |
| Full | direct features plus relational Prompt TSG motifs | FCI stable paths |
| Reduced representation | direct catalog feature states only | FCI stable paths |
| Association selection | direct features plus relational Prompt TSG motifs | association ranking |
| Double ablation | direct catalog feature states only | association ranking |

Reduced representation still derives every value from the canonical Prompt TSG. It removes
relational/motif queries from the causal-variable table; it does not introduce raw-text features or a
second feature authority.

The association selector is a frozen paper ablation. It ranks each allowed `X` against `Y` using a
pre-registered univariate G-square association statistic, deterministic ordering, and fixed top-`K`
budget on the discover split. It constructs no causal path and never replaces production FCI.

All configurations share the protocol in Section 4. RQ2 compares:

- Full versus Reduced representation for representation contribution;
- Full versus Association selection for causal-analysis contribution; and
- the Double ablation to expose interaction rather than selecting a convenient weakest baseline.

Each configuration reports the RQ1 funnel and hypothesis-specific ITT evidence. Additional diagnostics
include selected-feature overlap, FCI path stability, association-rank stability, and stage-specific
failure modes. Different selected hypotheses are never reduced to an unapproved pooled ATE.

RQ2 is an offline paper-evaluation layer. Its results cannot tune the production extractor, feature
catalog, FCI configuration, or final candidate family after confirmation.

## 9. RQ3 Operationalization

RQ3 studies safety-control hypotheses produced and frozen by the Full configuration with a
pre-registered risk-reduction direction. It does not perform a second favorable search and does not
claim catalog-wide completeness.

Allowed targets are editable Prompt-side requirements such as input validation, path normalization,
parameterized queries, authentication/authorization constraints, safe deserialization, sanitizer
requirements, and trust-boundary handling. Code-side guards, realized sanitizers, AST features, and
source-to-sink code paths are forbidden targets and mechanisms.

For ADD:

```text
delta_ADD = mean(Y | assigned TARGET_PATCH)
          - mean(Y | assigned NOOP_REWRITE)
expected delta_ADD > 0
```

For REMOVE:

```text
delta_REMOVE = mean(Y | assigned TARGET_REMOVE)
             - mean(Y | assigned NOOP_RETAIN)
expected delta_REMOVE < 0
```

ADD and REMOVE are separate protocols, blocks, multiplicity coordinates, and estimands. REMOVE may
only remove a provenance-bound positive clause and restore its attested security-neutral counterpart;
it never inserts an unsafe instruction. A feature is tested only for catalog-permitted operations
with sufficient pre-outcome task/counterpart support.

RQ3 reports:

- primary secure-and-functional target-minus-no-op ITT;
- task-clustered adjusted intervals and evidence levels;
- CWE-specific security as a pre-registered secondary outcome;
- target-minus-placebo and target-minus-generic specificity contrasts;
- ADD/REMOVE directional agreement where both protocols exist;
- target-change, semantic-compliance, block-freeze, and directional-change diagnostics.

No task is selected for the primary analysis because its observed/no-op code is insecure. All tested
features, including null and conflicting results, appear in the paper or artifact.

## 10. RQ4 Operationalization

RQ4 is a simplified expert perception study. It compares available explanation artifacts on a
shared-coverage case set. Coverage failures remain reported by RQ1; RQ4 therefore makes only a
conditional perceived-utility claim.

### 10.1 Presentation

All explanations use the same anonymous wrapper, typography, field order, context, and maximum length:

```text
Finding
Evidence
Expected direction
Experimental support / uncertainty
Suggested audit or repair action
```

Methods retain native evidence such as spans, perturbation deltas, rationales, concepts, rankings, or
SecAware Prompt-side hypothesis cards. All methods receive the same shared confirmation fields when
available. SecAware cards may include Prompt features, PAG uncertainty, ITT, control contrasts, and
treatment-fidelity diagnostics, but no code-side causal mechanism or individual-flip claim.

Cases and explanations are frozen before participant responses exist. Method identity is hidden. The
case-method assignment is balanced so each combination receives comparable ratings, while one
participant does not see multiple method versions of the same case.

### 10.2 Ratings

Qualified security, program-analysis, or LLM code-generation experts rate each explanation on a
five-point ordinal scale for:

1. clarity;
2. evidence sufficiency;
3. credibility;
4. actionability; and
5. overall usefulness.

Overall usefulness is the only primary human-study outcome. Other dimensions explain the ranking and
are secondary; they are not summed post hoc into an arbitrary composite.

### 10.3 Ranking and analysis

The primary analysis uses an ordinal mixed-effects model with method as a fixed effect and participant
and case as random effects. Methods are ranked by the pre-registered adjusted overall-usefulness
quantity, with uncertainty intervals and multiplicity-adjusted pairwise contrasts. Raw means and
per-dimension distributions remain descriptive outputs.

The study does not claim objective mechanism-identification or repair improvement. It therefore does
not require an accuracy reference panel or open-response double coding. It still requires a frozen
human-study protocol, participant eligibility rules, informed consent, an ethics/IRB determination,
case and rendering manifests, randomization, and an analysis plan.

## 11. Paper Revision Consequences

The manuscript revision must:

1. replace the old RQ sentences with Section 3;
2. remove structured code-mechanism variables and restrict `G`/`Z` language to Prompt-side features
   or motifs;
3. replace heuristic effect/targetability selection with TSG-constrained FCI, task-cluster bootstrap,
   stable possible paths, and pre-confirmation freeze;
4. describe text-native and graph-native intervention as run-locked execution modes rather than
   claiming every intervention is a graph patch;
5. replace paired counterfactual confirmation with family-specific randomized arm protocols;
6. replace per-protocol primary analysis with task-clustered ITT;
7. replace Bandit-default/optional-Semgrep language with the exact independent fail-closed Oracle;
8. add JCI secondary analysis and optional RFCI sensitivity boundaries;
9. replace strict/relaxed evidence labels with Section 6;
10. replace conditional flip claims with Section 7 diagnostics;
11. replace RQ1 and RQ2 table skeletons with fixed-budget funnel and ablation tables;
12. replace the original objective-task RQ4 design with the conditional perceived-utility study;
13. remove stale claims that RQ1H, external baselines, ablations, or the human study are already
    implemented; and
14. state that the current demo/mock `paper_v0` configuration is not a final paper run.

## 12. Required New Evaluation Work

The current core pipeline does not by itself complete all paper RQs. Later implementation planning
must separately scope:

- external method-native adapters and frozen mapping audits for RQ1;
- the four offline ablation configurations for RQ2;
- paper-facing RQ1/RQ2 funnel and evidence tables;
- RQ3 defensive-feature summary tables and directional diagnostics;
- benefit/harm bounds if retained;
- RQ4 case rendering, participant assignment, rating capture, and ordinal mixed-effects analysis;
- replacement of `configs/paper_v0.yaml` with a real frozen paper configuration and data manifest.

These additions may not weaken the core causal, Oracle, provenance, or failure boundaries.

## 13. Acceptance Criteria

The later manuscript and evaluation implementation are aligned with this design only when:

1. all four RQ sentences match Section 3 in substance;
2. every primary computational confirmation is randomized, task-clustered ITT;
3. mapping coverage is explicitly diagnostic and both conditional coverage and mapped yield at `K`
   are reported;
4. confirmed yield at `K` is the RQ1 method-level primary metric;
5. no pooled cross-hypothesis ATE is reported without a new approved estimand;
6. no target-change, semantic-compliance, or opportunity-conditioned outcome filter changes the ITT
   denominator;
7. target specificity requires direct target-control contrasts;
8. ADD and REMOVE evidence remains separate before any bidirectional label;
9. flip-style outputs are descriptive task-level diagnostics or explicit bounds, not individual causal
   effects;
10. RQ2 uses the frozen 2-by-2 design without tuning production behavior;
11. RQ3 limits claims to discovered, eligible Prompt-side safety-control features;
12. RQ4 ranks adjusted overall usefulness and limits its claim to perceived utility;
13. baseline, ablation, null, conflicting, and non-evaluable results are fully reported; and
14. all paper tables are reproducible from one frozen final run or from separately frozen, explicitly
    linked computational and human-study manifests.
