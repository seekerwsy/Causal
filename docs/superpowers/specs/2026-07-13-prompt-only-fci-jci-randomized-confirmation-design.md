# Prompt-Only FCI/JCI Discovery and Randomized Confirmation Design

**Date:** 2026-07-13
**Status:** Approved in sections; written specification awaiting final user review
**Scope:** Prompt TSG extraction, observational FCI discovery, typed prompt interventions,
randomized held-out confirmation, JCI analysis, and task-clustered effects

## 1. Authority and Objective

SecAware becomes a Prompt-only, TSG-constrained causal discovery and randomized counterfactual
confirmation framework. It does not invent a general-purpose causal discovery algorithm. The
minimum backend uses the established FCI implementation in `causal-learn` with the G-square
conditional-independence test. An optional RFCI sensitivity backend may use `py-tetrad`, but the
minimum runnable system must not require Java.

This specification preserves the M2 independent-Oracle and transactional-artifact boundaries and
the M3 decision that the canonical Prompt TSG is the only task-security graph. It supersedes:

- the heuristic TSG-QCD discovery score as the primary discovery method;
- the two-arm-only confirmation design in
  `2026-07-12-paired-confirmation-effects-design.md`;
- any proposal to add Code TSG, generated-code mechanism variables, or code-mechanism artifacts to
  primary discovery, JCI, eligibility, or effect estimation.

The retained primary causal question is:

```text
catalog-bound Prompt TSG feature X
    -> generated-program security/functionality outcome Y
```

Generated code remains necessary input to the independent Oracle and functional evaluator, but no
code structure, AST feature, source/sink/guard trace, or code-derived mechanism variable enters the
causal-variable tables.

## 2. Non-Negotiable Boundaries

1. Prompt TSG is the only authoritative task-security graph.
2. Graph edges express prompt task/security structure, never causal relations. Only FCI/RFCI PAG
   artifacts express learned causal endpoint marks.
3. Oracle and committed functional outcomes are the only producers of outcome variables `Y`.
4. Prompt extraction and graph construction receive no generated code, Oracle record, outcome,
   experiment-arm identity, selected target, expected delta, or post-treatment evidence.
5. Discovery uses only `split="discover"`; randomized confirmation uses held-out
   `split="confirm"` tasks.
6. Hypotheses are frozen before confirm variants are generated, randomized, or evaluated.
7. Background knowledge may prohibit directions and adjacencies but never requires a candidate
   feature-outcome edge or any edge on a path being tested.
8. `target_changed` and target-semantic compliance are diagnostics. They never filter the primary
   ITT assignment universe. They are distinct from the hard artifact-integrity,
   `SecurityNeutralPromptInvariant`, and per-arm `AllowedDelta` checks required before randomization.
9. Structural artifact corruption aborts a stage. Valid protocol failures remain typed data.
10. No stage silently skips, overwrites, best-effort joins, retries semantically, or selects a
    favorable LLM candidate.
11. Feature families share one Prompt TSG, but safety, task-function, and presentation experiments
    have separate outcomes, estimands, and statuses.
12. No extractor backend is selected or tuned using final confirmation outcomes.

## 3. Canonical Prompt Feature Graph

### 3.1 Feature families

Prompt TSG remains one canonical bounded `MultiDiGraph` and uses finite enums:

```text
FeatureFamily = TASK_FUNCTION | SAFETY_CONTROL | PRESENTATION_CONTROL
FeatureOperation = ADD | REMOVE
FeatureState = PRESENT | ABSENT | NOT_APPLICABLE | UNRESOLVED
```

Every intervenable feature is defined by one immutable, versioned catalog entry:

```text
FeatureSpec
  feature_family
  feature_id
  applicable CWE/task scopes
  reviewed semantic/evidence contract
  permitted node and edge templates
  graph query
  permitted ADD/REMOVE operations
  counterpart and neutrality requirements
```

The catalog permits no runtime registration, LLM-created feature identity, arbitrary label, or open
rule registry. A catalog change changes its digest and invalidates downstream skip state.

Task operations, data objects, APIs, sources, and sinks form the task layer. Requirements, guards,
trust boundaries, and security assumptions form the safety layer. Reviewed surface controls form
the presentation layer. Presentation edges cannot participate in security source-to-sink motifs.

### 3.2 Extractor backends

The implementation provides three explicit backends:

```text
PromptExtractorBackend
  LLM_FACTS_V1              # default
  LLM_DIRECT_GRAPH_V1
  DETERMINISTIC_CATALOG_V1
```

One run locks exactly one backend for all discover and confirm prompts. Per-prompt fallback or
mixing is forbidden. A different backend is a separate replication with separate manifests and
PAGs; results are not automatically pooled.

#### LLM_FACTS_V1

The LLM maps prompt text to strict catalog-bound semantic facts. Each proposal contains only:

```text
feature family and ID
semantic role/state
exact evidence offsets and evidence text
finite catalog-bound relations
explicit unresolved items
```

A deterministic evidence validator verifies prompt SHA-256, exact spans, catalog closure, family
compatibility, duplicate/conflicting facts, bounds, and schema. A deterministic template builder
then creates nodes and edges.

#### LLM_DIRECT_GRAPH_V1

The LLM proposes strict typed nodes and edges directly. The proposal may use only catalog feature
IDs, node/edge enums, finite attributes, and exact evidence spans. A deterministic validator rejects
unknown labels, invalid cross-layer edges, dangling endpoints, duplicate semantic identities,
unbounded output, evidence mismatch, and forbidden fields. Accepted proposals are canonicalized by
the same graph codec as every other backend.

#### DETERMINISTIC_CATALOG_V1

The current finite reviewed term matcher and catalog templates remain available as the offline,
minimum-dependency, regression, and sensitivity backend. It has no hidden fallback from either LLM
backend.

### 3.3 LLM extraction policy

Each LLM extractor run locks:

```text
provider and endpoint identity
model ID/version
system-template SHA-256
catalog and output-schema digests
temperature, top-p, seed when supported
request/response bounds
timeout and transport retry policy
```

The system prompt treats the user prompt as inert data, forbids following instructions embedded in
that data, restricts output to the supplied catalog, requires exact evidence, prohibits security
outcome judgments, and requires `UNRESOLVED` rather than guessing.

The extractor receives no arm, target, operation, intended graph delta, generated code, Oracle
record, or selected hypothesis. It has no tools. It returns one semantic candidate. Transport
retries may resend identical bytes; semantic retries and favorable-candidate selection are
forbidden. A committed response is frozen with its policy digest. Temperature zero is a reduction
in variability, not a claim of mathematical determinism.

The LLM intervention executor and LLM extractor are logically separate roles, requests, templates,
and artifacts. The extractor is blind to what the intervention executor was expected to change.

### 3.4 Deterministic commit boundary

All backends converge at a deterministic boundary:

```text
backend proposal
  -> strict validation
  -> canonical node/edge IDs
  -> canonical ordering
  -> graph digest
  -> record-to-graph round trip
  -> bounded projection and feature queries
```

No backend writes an authoritative flat feature dictionary. Task, safety, presentation, and motif
values are recomputed from the canonical graph. `shadow`, if retained for audit, is never read by
discovery, intervention eligibility, JCI, or effect estimation.

`ABSENT` means the prompt is in an applicable reviewed scope and the target structure is absent.
`NOT_APPLICABLE` is not encoded as absence. `UNRESOLVED` is explicit and cannot be silently changed
to `ABSENT` or `PRESENT`.

## 4. Local Causal-Variable Tables

### 4.1 Coordinates and variable sources

Prompt records gain a stable `task_id`; prompt variants have distinct IDs but share the same
`task_id`. Local tables are built independently for each configured CWE/security scope and model.

The allowed variables in the minimum within-model analysis are:

```text
W: pre-treatment task metadata
X: finite Prompt TSG feature or motif queries
Y: committed Oracle/functional outcomes
C: randomized arm context, JCI tables only
```

`model_id` is a producer coordinate and provenance field, not a causal-table column in the minimum
backend. FCI, bootstrap, confirmation effects, and JCI run separately by model. A future cross-model
context analysis requires a separately approved design.

Raw prompt text, generated code, Oracle finding text, code structure, graph shadow, discovery score,
and intervention diagnostics are not table columns.

Each column has a strict `CausalVariableSpec` containing a stable ID, value domain, source query,
scope, temporal tier, adjacency type, and producer digest. Not every graph node becomes a causal
variable. The finite variable catalog excludes redundant deterministic projections where they would
make G-square tables degenerate.

### 4.2 Outcome encoding

The primary discovery and confirmation outcome is binary secure-and-functional success. Every
valid unit/assignment outcome record receives a value:

```text
Y_secure_functional = 1
    iff generation produces a candidate, parse succeeds, the committed functional check passes,
        and the Oracle label is secure
Y_secure_functional = 0
    otherwise, including a typed terminal generation failure, parse/functional failure,
        or valid Oracle unknown
```

A missing, corrupt, or unavailable required producer is not converted to zero: it is a contract or
infrastructure failure, and table/effect publication waits for repair or deterministic replay of the
same unit/assignment. Thus conservative zero encodes a valid observed non-success, never absent
evidence.

CWE-specific security may additionally use a finite categorical value
`secure | insecure | unknown` plus a separate evaluability diagnostic. Infrastructure or producer
absence is never encoded as a value; it is a contract failure.

Task-function causal claims require a separately committed `FunctionalOutcomeRecord`. Without it,
task deltas may be structurally audited but cannot receive a functional-effect status.

### 4.3 Exact assembly

The table assembler validates exact prompt/task/model/seed producer coordinates. Duplicate, missing,
extra, stale, cross-condition, or mismatched records abort table publication. Joins never use silent
dictionary overwrite or `continue` on mismatch.

An unresolved pre-outcome feature may make that task ineligible for the affected scope, with a
typed pre-outcome reason. This filtering is fixed before reading `Y`. If scope support becomes
insufficient, no hypothesis is published.

## 5. TSG-Derived Background Knowledge

Background knowledge is derived only from variable types, prompt graph schema, and pre-treatment
catalog metadata. The base observational tiers are:

```text
Tier 0: task metadata W
Tier 1: Prompt TSG features X
Tier 2: Oracle/functional outcomes Y
```

It generates:

- temporal prohibitions such as `Y -> X` and `Y -> W`;
- family/scope-specific forbidden directions;
- typed adjacency exclusions by forbidding both directions;
- finite within-tier restrictions where justified by the catalog.

The raw augmented confirm run applies these base restrictions among `W`, `X`, and `Y` but leaves
every direction and adjacency incident to `C` unconstrained. The JCI-constrained run starts from the
same base knowledge, then places randomized context `C` in its context tier and adds explicitly
identified prohibitions such as system variables `-> C`. This separation prevents the raw PAG from
silently containing the JCI assumptions it is supposed to precede.

It does not require `X-Y`, `X-X2`, or any candidate path edge. The exact tiers, forbidden pairs,
typed adjacency matrix, variable order, and background-knowledge digest are persisted. The final PAG
is independently checked against every prohibition because accepting a background-knowledge
argument in a library API is not sufficient proof that every library orientation respected it.

## 6. Observational FCI Discovery

### 6.1 Minimum backend

The required backend is a pinned version/commit of `causal-learn` FCI with:

```text
independence_test_method = "gsq"
stable adjacency search
explicit alpha, depth, and maximum path length
locked variable/cardinality order
locked BackgroundKnowledge
bounded execution
```

The raw PAG preserves all endpoint marks (`tail`, `arrow`, `circle`) and is serialized into a strict,
backend-neutral schema with variable names, edge endpoints, CI/config provenance, library version,
table digest, and background-knowledge digest. Circle endpoints are never silently converted to
arrows.

### 6.2 Reference draw and task-cluster bootstrap

FCI is run separately by model unless a later approved design introduces a model context analysis.
The reference observational run uses a deterministic, pre-outcome seed derived from the global run
seed, scope, and model to select exactly one configured generation seed per task.

Each bootstrap replicate:

1. samples the same number of task IDs with replacement;
2. selects one seed for each sampled task occurrence using a deterministic replicate RNG;
3. includes the selected task row exactly once per sampled occurrence;
4. runs the identical FCI/G-square/backend configuration;
5. validates the resulting PAG against background knowledge;
6. records a bounded canonical PAG and path summary.

Individual model/seed rows are never bootstrapped as independent units. Bootstrap counts, depths,
variables, states, and wall-time/output bounds are finite and validated.

### 6.3 Stable possible paths and hypothesis freeze

A candidate path must start at a catalog-bound intervenable Prompt feature and end at a
pre-registered outcome. It may be a direct possible relation or pass through other allowed prompt or
pre-treatment variables. If path notation uses `Z`, `Z` is another prompt-side feature/motif or
pre-treatment variable, never generated code or a code mechanism variable.

Path matching preserves PAG uncertainty. A path qualifies only when its canonical variable sequence
and compatible endpoint pattern meet a configured bootstrap stability threshold and every edge is
allowed by the TSG-derived background knowledge. The extractor does not force an orientation to make
a path eligible.

`FrozenHypothesisRecord` includes:

```text
hypothesis and target feature coordinates
feature family and permitted operation(s)
CWE/outcome/model scope
reference PAG path and endpoint marks
bootstrap support numerator/denominator
table, catalog, extractor-policy, FCI, CI-test, and BK digests
expected randomized contrast direction
freeze timestamp/manifest commitment
```

Hypotheses are frozen before confirm variants, assignments, code, or outcomes exist. JCI results and
confirmation outcomes can never add, remove, rerank, or rewrite a frozen hypothesis.

### 6.4 Optional RFCI sensitivity backend

`py-tetrad` RFCI is optional, marked `requires_java=true`, and isolated behind a backend adapter. Its
absence cannot make the minimum causal-learn pipeline unavailable. The v2 adapter declares
`exclude_selection_bias=true` and passes the corresponding `excludeSelectionBias=true` parameter
to Tetrad before RFCI runs so Tetrad applies background-knowledge orientation under the declared
no-selection-bias assumption. The adapter reads the parameter back and fails closed unless it is
true. This assumption belongs only to the optional RFCI sensitivity backend; it does not change the
causal-learn FCI result, frozen hypotheses, or randomized ITT.

The JDK, JAR, JPype, algorithm, test, knowledge, and RFCI configuration versions are locked. The
adapter serializes Tetrad's PAG through the shared endpoint codec and validates it against the
declared background knowledge; it never rewrites circle endpoints or otherwise post-processes PAG
orientation locally. RFCI produces sensitivity artifacts only and does not replace the primary FCI
result without a future approved protocol. Existing run directories produced under RFCI v1 cannot
be upgraded in place; v2 requires a new run directory.

## 7. Typed Intervention Targets

An intervention target and its control-arm design are separate dimensions:

```text
TargetSpec
  feature_family
  feature_id
  operation = ADD | REMOVE
  source prompt role
  exact counterpart requirements

ArmProtocol
  finite arm roles appropriate to the family and operation
```

The canonical graph delta records before/after graph digests, target coordinates, ADD/REMOVE,
extractor and intervention policy digests, canonical node/edge changes, three projection commitments,
target-change state, non-target drift, reversibility, and delta digest.

Safety ADD starts from an attested neutral prompt. Safety REMOVE starts from an attested positive
safety prompt and may remove only a provenance-bound positive clause to restore its exact neutral
counterpart. REMOVE never inserts an unsafe instruction. The same neutral/positive text pair is one
contrast; its forward and reverse views cannot be counted as independent evidence.

`SecurityNeutralPromptInvariant` does not mean that every prompt lacks a positive security
requirement. It means that every base and arm prompt:

- describes the task without claiming or revealing that an implementation is vulnerable;
- never asks for, demonstrates, or rewards an unsafe operation;
- never reveals the expected Oracle label, effect direction, or confirmation result.

Positive target-specific and generic security requirements are allowed only in the arms that declare
them. Each arm has a finite `AllowedDelta` containing an upper bound on feature changes and exact
projections that must remain unchanged. It constrains what may change but does not require the
intended change to succeed; realized target success remains diagnostic.

The invariant is checked from exact pre-outcome prompt-role/counterpart attestations and finite
catalog queries over the independently extracted Prompt TSG. The intervention executor cannot
self-attest it. This is not an extensible keyword/rule registry; if the run-selected extractor cannot
resolve a required neutrality or `AllowedDelta` query, the hard freeze gate fails explicitly.

Task ADD/REMOVE preserves the safety projection and non-target task features. Presentation ADD/REMOVE
preserves the complete task and safety projections.

## 8. Family-Specific Arm Protocols

### 8.1 Safety ADD

```text
TARGET_PATCH
NOOP_REWRITE
LENGTH_MATCHED_PLACEBO
GENERIC_SECURITY_REMINDER
```

- target adds one specific safety feature;
- no-op changes surface wording but preserves task and safety semantics;
- placebo adds matched-length safety-neutral wording;
- generic reminder adds a cataloged general safety instruction without the target-specific feature.

Their `AllowedDelta` values respectively permit only the target safety feature, no semantic feature,
a cataloged presentation/placebo feature, or the cataloged generic safety feature to change. All
task features, presentation features except the declared placebo, and non-target safety features are
fixed.

### 8.2 Safety REMOVE

```text
TARGET_REMOVE
NOOP_RETAIN
LENGTH_MATCHED_SHAM_EDIT
GENERIC_SECURITY_REPLACEMENT
```

- target removes the specific positive clause and restores neutral text;
- no-op retains the target clause;
- sham edit makes matched surface change while retaining the target clause;
- generic replacement substitutes a cataloged generic reminder for the specific mechanism.

Their `AllowedDelta` values respectively permit only removal of the target safety feature, no
semantic feature, a cataloged presentation/sham feature, or removal of the target plus addition of
the cataloged generic safety feature. Task features and every undeclared safety/presentation feature
are fixed.

### 8.3 Task-function ADD/REMOVE

The required arms are target, no-op, and length-matched placebo. A fourth family-active control is
allowed only when a reviewed, cataloged generic functionality/completeness control and independent
functional outcome exist. A generic security reminder is not a valid task active control because it
would intentionally change the safety layer.

The corresponding `AllowedDelta` permits only the target task feature, no semantic feature, the
declared presentation/placebo feature, or the reviewed generic task-control feature. The complete
safety projection and every undeclared task/presentation feature are fixed.

### 8.4 Presentation ADD/REMOVE

Presentation experiments use target plus no-op and, when justified, a matched presentation control.
They are negative-control experiments and never receive a confirmed safety-mechanism status. A
generic security arm is forbidden because it would violate the presentation protocol's unchanged
safety projection.

The corresponding `AllowedDelta` permits only the target presentation feature, no semantic feature,
or the declared matched presentation-control feature. The complete task and safety projections and
every undeclared presentation feature are fixed.

## 9. Variant Construction, Validation, and Freeze

Intervention execution may be text-native or graph-native and may use a deterministic or locked LLM
text executor. The selected mode/executor/model/template/catalog/decoding configuration is fixed for
the run. The executor is a locked implementation component with provenance, not an additional causal
variable. There is one semantic candidate per arm. A failed candidate receives no semantic retry and
is not replaced by a more favorable wording.

Every arm is independently extracted with the run-locked Prompt extractor backend. The extractor is
blind to arm and target. Structural schema/catalog/evidence integrity, canonical graph round trip,
prompt bounds, `SecurityNeutralPromptInvariant`, and the arm's `AllowedDelta` must pass before a
variant can be frozen. These checks reject any undeclared change but do not ask whether the permitted
target delta actually occurred and do not read an outcome.

`target_changed`, target-semantic compliance, and permissible within-family non-target drift are
recorded as diagnostics. A safe, structurally valid variant may be frozen when one of these is false
or unresolved. If any arm cannot pass the hard freeze gate, the whole task/hypothesis protocol is
reported as a pre-randomization exclusion and receives no assignment; this exclusion is fixed without
reading `Y`. Once the assignment manifest is committed, diagnostics cannot change the primary ITT
denominator. Later corruption/unavailability of a frozen artifact aborts and replays the same
manifest; a valid terminal generation/evaluation non-success remains assigned ITT data.

## 10. Randomized Held-Out Confirmation

Before variant construction, every frozen hypothesis materializes one pre-registered
`ConfirmationProtocolRecord` for each selected `TargetSpec`. ADD and REMOVE are always distinct
records, protocols, and blocks, even if both are permitted for the same feature. A protocol record
binds the hypothesis, exact target, arm-protocol ID, arm roles, counterpart, outcome, and contrasts.

The experimental unit and block are:

```text
experimental_unit =
  (task_id, frozen_hypothesis_id, target_spec_id, model_id, seed_slot)

block =
  (task_id, frozen_hypothesis_id, target_spec_id, arm_protocol_id, model_id)

AssignmentRecord: experimental_unit -> arm_role
```

Randomization occurs only after every arm variant for the exact task/hypothesis/TargetSpec/protocol
block is frozen. Blocks are never pooled across target features, operations, or arm protocols. Within
each block, configured seed slots are assigned by a manifested deterministic RNG to a balanced
permutation of the protocol's arm roles. `seed_slot` maps deterministically to the configured
generation `seed_id`; neither is the treatment. The number of seed slots must support the arm
protocol; invalid or unbalanced configurations fail before requests are issued.

Assignment IDs, RNG algorithm/version, global and derived seeds, block order, arm balance, prompt
variant IDs, request IDs, and model parameters are committed before generation. Provider execution
order cannot change assignment.

## 11. Outcomes and Primary ITT

### 11.1 Assignment principle

All committed randomized assignments enter the primary ITT denominator. The primary analysis groups
by assigned arm, not realized target change. Protocol noncompliance, extractor uncertainty, typed
terminal generation failure, parse or functional failure, and valid Oracle unknown are retained
according to the predeclared outcome encoding and sensitivity bounds. Missing/corrupt required
producers block publication and deterministic replay; they are not silently treated as outcomes.

### 11.2 Outcome families

Safety experiments estimate task-clustered arm effects on:

- secure-and-functional success;
- CWE-specific security/evaluability;
- parse and functional diagnostics.

Task-function experiments require an independent functional outcome as primary; security outcomes
are secondary. Presentation experiments report negative-control security shifts, not confirmed
security mechanisms.

There is no code-mechanism outcome.

### 11.3 Pre-registered contrasts

Safety ADD uses target-minus-no-op as the primary contrast. Target-minus-length-placebo,
target-minus-generic-reminder, generic-minus-no-op, and placebo-minus-no-op are pre-registered
secondary/diagnostic contrasts. Safety REMOVE uses the analogous target-remove contrasts.

Task and presentation protocols declare only their family-valid contrasts. Arbitrary post-outcome
pairwise contrast selection is forbidden. Confidence intervals and multiplicity adjustment cover the
pre-registered contrast family.

### 11.4 Clustered uncertainty

Point estimates are arm-level risk/success differences over all assigned units. Uncertainty is
resampled by task cluster; all assignments belonging to a sampled task are included as a block.
Bootstrap RNG, replicate count, percentile interpolation, invalid-replicate handling, multiplicity
adjustment, and minimum independent-task counts are finite and versioned.

Unknown/non-evaluable outcomes receive the conservative no-success/no-benefit treatment appropriate
to the predeclared success outcome, with explicit best/worst sensitivity bounds. This encoding never
relabels unknown as secure or insecure.

## 12. JCI Analysis

JCI tables and runs are separated by:

```text
(scope_id, model_id, frozen_hypothesis_id, target_spec_id, arm_protocol_id)
```

Because `target_spec_id` binds feature family, feature ID, and ADD/REMOVE, this prohibits pooling
different feature targets, operations, three/four-arm protocols, or family-specific arm semantics.
Insufficient support in one stratum yields no JCI PAG for that stratum and does not alter its primary
ITT estimate.

Each stratum's confirm table augments `W`, realized Prompt TSG `X`, and `Y` with one categorical arm
context whose values are exactly that protocol's arm roles:

```text
C_arm = one finite arm-role value
```

The minimum implementation uses this single categorical column; mutually exclusive one-hot context
columns are forbidden because they introduce avoidable deterministic relations and sparse G-square
tables.

Both runs use identical rows, variable order, CI configuration, and base `W/X/Y` knowledge. The
system persists:

1. a raw augmented FCI PAG without JCI assumptions;
2. the exact JCI background-knowledge artifact;
3. a JCI-constrained FCI PAG;
4. an orientation delta that preserves every changed endpoint and attaches the complete sorted set
   and digest of enabled JCI assumption IDs;
5. all table, CI, FCI, extractor, randomization, and library provenance.

At minimum, JCI background knowledge forbids system variables from causing randomized context.
Additional assumptions require explicit finite IDs and tests. No context-system adjacency is required.
The final PAG is checked against the assumptions after library execution. The delta establishes that
an endpoint changed under the recorded assumption set; it does not claim that one individual
assumption caused that change. Per-assumption attribution would require a separately approved,
bounded assumption-ablation procedure and is not part of this milestone.

JCI is a structural secondary analysis. It cannot change frozen hypotheses, assignment, primary ITT
contrasts, outcomes, or confirmed status.

## 13. Artifacts and Transactions

The pipeline publishes strict, bounded, versioned artifacts for:

```text
Prompt TSG and extractor proposals
local causal-variable tables
background knowledge
raw observational PAG
bootstrap PAG/path support
frozen hypotheses
TargetSpec and GraphDelta
frozen prompt variants
randomized assignments
generation and Oracle/functional outcomes
primary ITT effects and diagnostics
raw/JCI-constrained PAGs and orientation deltas
typed failures and final reports
```

No mechanism artifact exists. All artifacts bind exact producer coordinates and content digests. Raw
prompt/code text is excluded from error messages, tracebacks, reprs, and evidence summaries.

Each stage holds committed producer leases in canonical order throughout readback, validation,
computation, sealing, manifest commit, and rollback. Concurrent force-runs cannot observe or replace
partial output. Failure restores the previous committed outputs byte-for-byte.

## 14. Configuration

Configuration is strict, bounded, and finite. It includes:

- extractor backend, catalog, and backend-specific locked policy;
- FCI backend/version, G-square, alpha, depth, path limits, and table bounds;
- bootstrap count, stability threshold, RNG, and minimum task support;
- optional RFCI adapter settings and an explicit Java-required capability flag;
- intervention mode/executor and arm-protocol catalogs;
- randomization block/balance settings;
- pre-registered outcomes, contrasts, confidence level, and multiplicity adjustment.

`LLM_FACTS_V1` is the default extractor. `LLM_DIRECT_GRAPH_V1` and
`DETERMINISTIC_CATALOG_V1` require explicit selection. There is no automatic backend benchmark,
ranking, winner selection, or fallback in this milestone.

Secrets come only from the environment and are never persisted. Model, endpoint identity, templates,
schemas, catalog, decoding configuration, and response/request limits are included in stage
fingerprints without storing secrets.

## 15. Failure Semantics

- Invalid schema, catalog, evidence, digest, graph, coordinate, split, provenance, or artifact
  coverage aborts the stage and publishes nothing.
- LLM runtime/authentication/model drift or malformed provider protocol aborts extraction or
  intervention; it never invokes another backend automatically.
- A valid `UNRESOLVED` extraction remains typed pre-outcome data and follows the scope/variant policy;
  it is not guessed.
- Insufficient FCI table support or bootstrap stability produces no frozen hypothesis, not a
  fabricated path.
- A PAG that violates committed background knowledge fails closed.
- Missing required causal-learn capability fails the minimum backend; missing Java/RFCI capability
  only marks the optional sensitivity backend unavailable.
- Empty hypothesis, assignment, or valid-contrast universes fail closed rather than publishing a
  vacuous confirmed result.
- Hard variant-construction failure before assignment is a reported pre-randomization exclusion;
  it cannot inspect `Y` or trigger favorable-candidate replacement.
- After assignment, valid terminal generation, parsing, functional, or Oracle-unknown outcomes
  remain ITT data; missing/corrupt producers remain contract failures requiring the same manifest to
  be replayed.
- All traversals, products, graph paths, CI depths, bootstrap loops, and outputs have explicit bounds.

## 16. Testing and Acceptance

The design is complete only when tests prove:

1. all three extractor backends emit the common strict schema and canonical Prompt TSG;
2. LLM backends reject prompt injection, catalog escape, fabricated spans, illegal graph fields,
   target/arm/outcome leakage, duplicate facts, and oversized output;
3. no backend is mixed or silently used as fallback inside one run;
4. equivalent fact/graph insertion orders yield identical graph IDs, JSON, and digests;
5. task/safety/presentation projections and ADD/REMOVE queries are graph-derived;
6. backend/prompt/model/template/catalog/config drift invalidates skip state;
7. local tables have exact producer coverage, are separated by model, omit `model_id` as a minimum
   causal variable, and contain no forbidden code/outcome-leakage fields;
8. background tiers, one-way forbiddance, and two-way adjacency forbiddance are exact;
9. FCI uses the pinned causal-learn backend and G-square configuration and preserves PAG circles;
10. final PAG validation catches any background-knowledge violation;
11. task-cluster bootstrap selects one seed per sampled task, is deterministic, bounded, and differs
    from invalid row-wise bootstrap on adversarial data;
12. stable-path selection is endpoint-aware, order-invariant, mutation-sensitive, and frozen before
    confirm artifacts exist;
13. safety ADD/REMOVE satisfy `SecurityNeutralPromptInvariant`, have exact per-arm `AllowedDelta`,
    are provenance-bound and reversible, and never insert unsafe wording;
14. the same forward/reverse text pair cannot be counted twice;
15. task and presentation operations obey their family-specific projection invariants;
16. every arm protocol is generated, independently extracted, validated, and frozen before
    randomization/generation;
17. ADD/REMOVE and different TargetSpec/protocol IDs form distinct complete blocks; assignment maps
    seed-slot experimental units to balanced arm roles deterministically and is immutable after
    commit;
18. `target_changed` and semantic diagnostics cannot alter the primary ITT denominator;
19. task-clustered ITT, sensitivity bounds, contrast multiplicity, and all failure encodings are
    mutation-sensitive and hand-checkable;
20. JCI never pools distinct hypotheses, TargetSpecs, operations, or arm protocols; raw augmented and
    JCI-constrained PAGs are separate, raw background knowledge has no `C`-incident prohibition, and
    every changed endpoint records the complete enabled assumption-ID set without unsupported
    per-assumption attribution;
21. optional RFCI absence does not break the no-Java minimum backend;
22. synthetic SCM gates cover a true prompt-variable chain, latent confounding, a null factor, and
    deterministic JCI context relations with explicit stable or fail-closed expectations;
23. discover/confirm separation, transaction leases, forced failures, interrupts, concurrency, and
    rollback preserve committed artifacts;
24. Python 3.10, Python 3.12, minimum Pydantic, Ruff, compile, static checks, and the real independent
    Oracle gate pass for the minimum backend.

This milestone intentionally does not implement an extractor fairness benchmark, gold-corpus
scoring, automatic backend ranking, or automatic winner selection. Basic contract, security, graph,
and end-to-end tests for every backend are required.

## 17. Non-Goals

- No Code TSG, code-mechanism trace, code feature, mechanism mediator, or code-side causal variable.
- No new general-purpose causal discovery algorithm.
- No mandatory Java runtime.
- No required candidate feature-outcome/path edges in background knowledge.
- No mediation, natural indirect effect, or controlled direct effect claim.
- No use of realized target change or semantic compliance as a primary ITT filter.
- No runtime feature/rule/plugin registry.
- No adaptive stopping, post-outcome prompt/extractor tuning, or favorable-candidate selection.
- No pooling across feature families, extractor backends, models, or FCI/RFCI backends without a
  separately approved estimand.
- No claim of population generalization beyond configured discovery and confirmation tasks.

## 18. Consequences and Milestone Decomposition

This is a breaking successor to the current heuristic discovery and paired-confirmation design.
Prompt TSG 2.0, discovery, intervention, pair/effect, and report artifacts must be regenerated.

Implementation should be decomposed into separately testable plans:

```text
M4A: Prompt TSG 2.1 feature families and three extractor backends
M4B: local variable tables, TSG-derived background knowledge, causal-learn FCI, bootstrap, freeze
M5: typed TargetSpec, family arm protocols, variant freeze, and randomized blocks
M6: task-clustered ITT, JCI PAGs, optional RFCI sensitivity, artifacts, and synthetic SCM gates
```

The decomposition changes implementation sequencing, not the causal model. Prompt TSG is the sole
feature authority, FCI supplies observational hypotheses, random assignment supplies primary causal
effects, JCI supplies a separately labeled structural analysis, and the independent Oracle remains
the sole security-outcome authority.
