# SecAware Paper Causal Boundaries

Use this reference when the manuscript touches causal discovery, prompt
representation, interventions, outcomes, effects, evidence levels, or RQ
operationalization. The two approved specifications remain authoritative:

- `docs/superpowers/specs/2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md`
- `docs/superpowers/specs/2026-07-22-paper-research-questions-design.md`

## Representation and Variables

- The authoritative representation is a prompt-side typed task-security graph
  (Prompt TSG).
- Prompt TSG edges encode typed task/security structure. They are not causal
  edges.
- Generated code is input only to the independent security Oracle and
  functional evaluator. It is not represented as a Code TSG and does not
  supply code-side causal mechanism variables.
- Build local causal-variable tables separately for each CWE/security scope
  and model.
- Use pre-treatment metadata `W`, Prompt TSG features or motifs `X`, outcome
  variables `Y`, and arm-context variables `C` only in JCI analyses.
- Preserve mechanism/outcome provenance separation. Oracle labels must not
  leak into feature extraction, hypothesis formation, prompt validation, or
  assignment.

## Discovery Contract

- The minimum backend is `causal-learn` FCI with a G-square conditional
  independence test and no Java requirement.
- Background knowledge comes from Prompt TSG temporal tiers, forbidden
  directions, and typed adjacency restrictions. It must not require the
  candidate edges being tested.
- The reference observational draw selects one seed at random per task.
- Uncertainty and stability use task-cluster bootstrap resampling, not
  row-level resampling.
- Extract stable, endpoint-aware possible paths from PAGs. Freeze selected
  hypotheses, target mappings, expected directions, and analysis scope before
  confirmation outcomes are observed.
- Represent randomized arms as JCI context variables in a secondary analysis.
  Preserve both the raw augmented PAG and the JCI-constrained PAG plus explicit
  orientation deltas.
- Optional py-tetrad RFCI is a sensitivity backend. Backend failure remains a
  recorded sensitivity result and cannot block the minimum causal-learn path.

## Intervention Contract

The run locks one execution design: text-native or graph-native, and a
deterministic renderer or a locked LLM executor. The choice is implementation
provenance, not an extra causal variable.

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

Before randomization, validate and freeze every prompt variant. Hard gates
cover schema, provenance, security-neutral task preservation, family-specific
AllowedDelta, and absence of leaked outcome information. After assignment,
`target_changed`, semantic compliance, and non-target drift are diagnostics;
they never filter the primary ITT denominator.

Randomize within locked task/hypothesis/TargetSpec/protocol/model blocks and
balance seed slots across arms. Do not filter the confirmation pool by an
observed insecure outcome.

## Effect and Evidence Contract

- Primary effects are assigned-arm, task-clustered ITT contrasts.
- The primary contrast is target versus the operation-matched no-op arm.
- The primary outcome is secure-and-functional. CWE-specific security is a
  secondary outcome.
- Placebo and generic-reminder contrasts diagnose specificity and generic
  security-prompt effects.
- Do not pool across hypothesis, target, operation, model, or CWE unless a
  separate estimand was approved in advance.
- Report task improvement, harm, and tie rates only as descriptive transition
  diagnostics. Do not call them individual causal flips.

Approved evidence levels:

1. Observational Candidate
2. Confirmed Intervention Effect
3. Target-Specific Effect
4. Bidirectional Support
5. Directionally Consistent but Inconclusive
6. Null / Conflicting / Non-Evaluable

## Research Questions

Use these sentences exactly:

- **RQ1.** How effectively can different methods discover and confirm
  security-relevant prompt-side mechanisms in LLM code generation?
- **RQ2.** How do SecAware's structured representation and causal analysis
  components contribute to mechanism discovery and confirmation?
- **RQ3.** Which prompt-side defensive interventions effectively reduce
  insecure code generation?
- **RQ4.** How do security experts rate and rank the perceived quality and
  usefulness of explanations produced by different methods?

### RQ1

Use the fixed candidate budget `K` funnel:

`K -> N_native -> N_mapped -> N_protocol -> N_randomized -> N_confirmed`

The method-level primary endpoint is confirmed yield at `K`. Mapping coverage,
protocolization, block-freeze coverage, randomized yield, and conditional
confirmation are bridge or diagnostic measures. Run all methods on the same
discover and confirm pools with the same generation, Oracle, and ITT pipeline.

### RQ2

Use the preregistered two-by-two design:

| Variant | Representation | Selection |
|---|---|---|
| Full | direct and relational Prompt TSG motifs | FCI |
| Reduced representation | direct catalog feature states | FCI |
| Association selection | direct and relational Prompt TSG motifs | univariate G-square association |
| Double ablation | direct catalog feature states | univariate G-square association |

### RQ3

Evaluate ADD and REMOVE as separate protocols. Primary claims use target versus
operation-matched no-op ITT effects; placebo and generic arms test specificity.
Observed baseline insecurity is neither an eligibility condition nor an ITT
denominator filter.

### RQ4

Compare method outputs in one neutral wrapper with: Finding, Evidence,
Expected direction, Experimental support or uncertainty, and Suggested audit
or repair action. Rate clarity, evidence sufficiency, credibility,
actionability, and overall usefulness. Overall usefulness is primary. Analyze
ordinal ratings with method as a fixed effect and participant and case as
random effects. This RQ does not claim objective mechanism-identification or
repair accuracy and does not require a reference panel or double-coded open
responses.

## Implementation-Status Boundary

The core supports Prompt TSG extraction, local tables/background knowledge,
causal-learn FCI, bootstrap stability, hypothesis freezing, intervention
families, randomized blocks, task-clustered ITT, JCI, optional RFCI, and the
Oracle/functional path. The repository does not yet complete all paper RQs.
Do not claim completion of external method-native adapters and mapping audits,
offline RQ2 ablations, final paper tables and RQ3 summaries, the RQ4 study, or
the final frozen paper run. Demo/mock `paper_v0` artifacts are not final paper
evidence.
