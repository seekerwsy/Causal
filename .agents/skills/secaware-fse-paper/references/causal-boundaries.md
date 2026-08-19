# SecAware Paper Causal Boundaries

Use this reference when the manuscript touches causal discovery, prompt
representation, interventions, outcomes, effects, evidence levels, or RQ
operationalization. New-protocol work follows the prospective successor:

- `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`

The following specifications remain authoritative for legacy runs that bind
their schemas and manifests:

- `docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md`
- `docs/superpowers/specs/2026-07-22-paper-research-questions-design.md`

## Representation and Variables

- The authoritative representation is a prompt-side typed task-security graph
  (Prompt TSG).
- Prompt TSG edges encode typed task/security structure. They are not causal
  edges.
- Generated code is input to the independent security Oracle and functional
  evaluator. A separately provenanced analyzer may additionally produce
  implementation diagnostics, but generated code is not represented as a
  Code TSG and supplies no primary-PAG variable or causal mediator.
- Build local causal-variable tables separately for each CWE/security scope
  and model.
- Use pre-treatment metadata `W`, natural Prompt TSG variables `X^0`, and
  outcome variables `Y^0` in discovery. Randomized arm `A` is the treatment in
  confirmation; post-intervention `X^{A,R}` is a fidelity diagnostic.
- A hypothesis is `h=(C_q,f,a,Q_h,Y)`: one non-actionable context query, one
  actionable feature, ADD/REMOVE, a finite realization distribution, and one
  outcome. A relational motif cannot itself be assigned.
- Context eligibility passes only when the frozen four-valued context query is
  `PRESENT`. ADD requires an applicable, resolved `ABSENT` target; REMOVE
  requires a provenance-bound `PRESENT` positive target and a pre-attested
  task-preserving neutral counterpart. All other states remain distinct
  pre-outcome exclusions.
- Preserve mechanism/outcome provenance separation. Oracle labels must not
  leak into feature extraction, hypothesis formation, prompt validation, or
  assignment.

## Discovery Contract

- The minimum backend is `causal-learn` FCI with a G-square conditional
  independence test and no Java requirement.
- Treat simultaneously authored Prompt features as one temporal tier. Do not
  interpret same-tier feature directions or `X-X-Y` paths as Prompt-feature
  mediation without a separately approved authoring SCM.
- Background knowledge comes from Prompt TSG temporal tiers, forbidden
  directions, and typed adjacency restrictions. It must not require the
  candidate edges being tested.
- Report a fixed-reference request-slot task bootstrap, a task-plus-slot
  two-level bootstrap, and a multi-slot task-level sensitivity analysis.
- Uncertainty and stability resample `semantic_task_cluster_id`, never rows or
  generation requests as independent units.
- Prioritize endpoint-aware feature/outcome adjacency, possible ancestry, or
  context-conditioned relevance. Freeze selected hypotheses, the intervention
  bridge, expected directions, realization distribution, and analysis scope
  before confirmation outcomes are observed.
- Audit every background-knowledge source, raw/full PAG delta, leave-family-out
  result, and a wrong-but-plausible BK perturbation.
- JCI is an appendix exploratory analysis. Preserve raw and constrained PAGs
  when it is run, but it cannot change any main result.
- Optional py-tetrad RFCI is a sensitivity backend. Backend failure remains a
  recorded appendix result and cannot block the minimum causal-learn path.

## Intervention Contract

The run locks one execution design: text-native or graph-native, and a
deterministic renderer or a locked LLM executor. The choice is implementation
provenance, not an extra causal variable. The rewrite operator is
`Gamma_{h,A,R}(P^0)=P^{A,R}` and its task, context, and non-target invariants
are explicitly extractor-relative.

Safety-ADD arms:

- `TARGET_PATCH`
- `NOOP_REWRITE`
- `LENGTH_MATCHED_PLACEBO`
- `GENERIC_SECURITY_REMINDER`

Safety-REMOVE arms:

- `TARGET_REMOVE`
- `NOOP_RETAIN`
- `LENGTH_MATCHED_SHAM_EDIT`
- `GENERIC_SECURITY_REPLACEMENT`

Before randomization, freeze task-independent realization specifications and
their probabilities under `Q_h`, then validate a complete matched task-specific
arm bundle for every eligible task and realization. Hard gates
cover schema, provenance, security-neutral task preservation, family-specific
AllowedDelta, and absence of leaked outcome information. After assignment,
`target_changed`, semantic compliance, and non-target drift are diagnostics;
they never filter the primary ITT denominator.

The assignment unit is one `request_randomness_slot`; the complete randomized
block binds semantic cluster, task, hypothesis, target, global realization
specification, task realization bundle, model, and arm protocol; the highest
independent cluster is `semantic_task_cluster_id`. Balance arms within blocks
and do not filter the confirmation pool by an observed insecure outcome.

## Effect and Evidence Contract

- Primary effects are assigned-arm, task-clustered ITT contrasts.
- The primary contrast is target versus the operation-matched no-op arm.
- The prospective primary safety outcome is oracle-evaluable secure-code
  yield: `Y_C * Y_E * I(secure)`. Secure-and-functional joint success is the
  key practical secondary outcome.
- Report code-valid yield `Y_C`, Oracle support `Y_E`, unknown rate,
  arm-conditional coverage, and best/worst bounds separately.
- Placebo and generic-reminder contrasts diagnose specificity and generic
  security-prompt effects.
- Do not pool across hypothesis, target, operation, model, or CWE unless a
  separate estimand was approved in advance.
- The main estimand averages assigned-arm target-minus-no-op effects over the
  frozen task population, `Q_h` realization distribution, and request
  randomness. It is not `do(X=1)` or a universal wording effect.
- Simultaneous intervals and selector comparisons resample semantic task
  clusters while carrying all descendant hypotheses, arms, models, methods,
  and realizations.
- Report task improvement, harm, and tie rates only as descriptive transition
  diagnostics. Do not call them individual causal flips.

Prospective evidence levels:

1. Observational Candidate
2. Randomized Policy Effect
3. Target-Specific Policy Effect
4. Realization-Robust Policy Effect
5. Cross-Model Replication
6. Bidirectional Support
7. Directionally Consistent but Inconclusive
8. Null / Conflicting / Non-Evaluable

## Research Questions

Use these three main-paper sentences exactly for the prospective protocol:

- **RQ1.** How effectively can different methods prioritize prompt
  interventions that generalize to held-out tasks?
- **RQ2.** How do SecAware's structured representation and causal
  prioritization contribute to successful intervention selection?
- **RQ3.** Which prompt-side security interventions reliably improve secure
  code generation?

### RQ1

The primary track is a shared candidate universe with the same candidates and
information budget for FCI, association, regularized prediction, expert, and
random selectors. Use strict confirmed yield at `K` and paired selector
utility differences. A separate native-system track retains the fixed funnel:

`K -> N_native -> N_mapped -> N_protocol -> N_randomized -> N_confirmed`

Native-track confirmed yield at `K` is an end-to-end endpoint. Mapping coverage,
protocolization, block-freeze coverage, randomized yield, and conditional
confirmation are bridge or diagnostic measures. Run all methods on the same
discover and confirm pools with the same generation, Oracle, and ITT pipeline.

### RQ2

Separate selector-only comparison from representation comparison. Selector
comparison holds the universe fixed. Representation comparison contrasts a
direct-feature universe with a direct-plus-context universe and reports
end-to-end yield, coverage, protocolization, and effect distributions without
calling it pure selector superiority.

### RQ3

Evaluate ADD and REMOVE as separate protocols. Primary claims use target versus
operation-matched no-op ITT effects; placebo and generic arms test specificity.
Observed baseline insecurity is neither an eligibility condition nor an ITT
denominator filter.

The former RQ4 expert-perception study is preserved only as a separately
versioned optional study or future paper. It is not a main-paper RQ and cannot
validate causal discovery or randomized security effects.

## Implementation-Status Boundary

The legacy core supports Prompt TSG extraction, local tables/background
knowledge, causal-learn FCI, bootstrap stability, hypothesis freezing,
intervention families, randomized blocks, task-clustered ITT, JCI, optional
RFCI, and the Oracle/functional path. The prospective bridge, shared selector
universe, context/actionable split, multi-realization blocks,
semantic-task-cluster inference, decomposed primary outcome, and complete paper
evaluation are specifications until implemented and verified. Do not describe
them as executed. Demo, smoke, exploratory, or legacy artifacts are not final
prospective-protocol paper evidence.
