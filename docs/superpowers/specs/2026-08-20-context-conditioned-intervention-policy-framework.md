# Prompt Mechanism Study Context-Conditioned Intervention-Policy Framework

**Date:** 2026-08-20

**Status:** `SPECIFIED_DRAFT`

**Prospective protocol ID:** `phase-context-policy-v3`

**Prospective schema family:** `3.x` (not yet authorized for formal execution)

**Draft revision:** 2026-09-01 discovery-population, discoverability, and post-confirmation analysis patch

**Scope:** Prospective theory, discovery, hypothesis selection, randomized confirmation,
inference, and paper-facing research questions

**Terminology:** The paper-facing and prospective-protocol name for the highest
independent sampling/resampling coordinate is **task unit** (`task_unit_id`).
This document's existing mathematical symbol `c` and frozen physical names
containing `semantic_task_cluster_id` denote that same unit; "cluster" is
otherwise reserved for the preceding source-record deduplication operation.
This terminology change does not alter membership, weights, estimands, or any
frozen artifact.

## 1. Authority and Supersession

This document is the review-candidate successor to:

- `2026-07-13-prompt-only-fci-jci-randomized-confirmation-design.md`; and
- `2026-07-22-paper-research-questions-design.md`.

It preserves their Prompt-only representation, independent-Oracle, held-out randomization,
assigned-arm ITT, fail-closed provenance, four-arm safety protocols, and no-general-purpose-causal-
algorithm boundaries. It prospectively supersedes the following clauses:

1. one symbol `X` denoting both a natural Prompt feature and a post-intervention diagnostic;
2. a relational motif being directly treated as an editable intervention target;
3. secure-and-functional success being the sole primary security outcome;
4. `task_id` being sufficient to express every independent sampling cluster;
5. a randomization block that omits textual realization;
6. JCI and RFCI occupying the main paper method narrative; and
7. the expert-perception study being used to validate computational causal or repair claims.

The previous files and every artifact produced under them remain immutable historical records. They
must not be edited in place or represented as having been generated under this framework. This
framework remains `SPECIFIED_DRAFT` until every author decision, qualification artifact, budget
Gate, implementation, independent verifier, and reviewer reproduction required below closes. Only
then may its status become `FROZEN`. A run must declare either a legacy protocol or the frozen form
of this protocol; it may not silently mix their hypotheses, estimands, schemas, data roles, or
evidence labels.

## 2. Scientific Positioning

Prompt Mechanism Study is not a new general-purpose causal-discovery algorithm and does not claim that FCI recovers
the unique causal mechanism of Prompt authoring. It is a method for:

```text
typed context-conditioned intervention hypotheses
  -> observational prioritization under latent-variable uncertainty
  -> frozen multi-realization Prompt policies
  -> held-out randomized security evaluation
```

The central scientific problem is budgeted hypothesis selection. Given a fixed discovery dataset and
a finite intervention vocabulary, a selector receives exactly `K` slots and prioritizes policies for
held-out randomized confirmation. In the Atomic Full selector, FCI supplies a latent-confounding-
aware local structural-admissibility Gate and the shared cross-fitted first-order risk-difference
score supplies the rank. Atomic RD-only uses the same universe, rows, folds, score, tie-break, slots,
bridge, and confirmation but does not read the FCI Gate. Pair Full and Pair No-Relation analogously
share an independently compatible universe and one second-order risk-difference score; only Pair
Full reads the qualified Prompt-TSG relation Gate. Neither FCI nor a Prompt-TSG relation identifies
the final effect. Random assignment identifies the frozen Prompt-policy effect.

The main contribution is therefore the combination of:

1. a typed language that binds an immutable task/security context to one editable Prompt feature;
2. a provenance-complete bridge from observational evidence to a realizable Prompt policy;
3. a fair shared-universe comparison of hypothesis selectors; and
4. external causal validation on held-out semantic task clusters.

The paper may summarize this procedure in three macro phases: **discovery and freeze**
(representation, prioritization, and hypothesis freeze), **randomized intervention**
(intervention/randomization and measurement), and **causal reporting** (outcome assembly and
inference/reporting). This is presentation only. The reviewer artifact retains the seven explicit
stages, their immutable boundaries, and one linear execution path.

## 3. Non-Negotiable Boundaries

1. Prompt TSG is the only authoritative task-security graph.
2. Prompt TSG edges encode task/security relations, never learned causal edges.
3. Generated code is not converted into a Code TSG and contributes no variable to the primary
   observational PAG.
4. Security outcomes come only from the independent Oracle. Functional outcomes come only from the
   committed functional evaluator.
5. Optional implementation markers derived from generated code are post-assignment diagnostics.
   They are not mediators, intervention targets, Oracle substitutes, or primary discovery variables.
6. Every task unit is governed by a content-addressed role manifest. `QUAL_DEV`, `QUAL_ACCEPT`,
   `DISCOVERY`, `CONFIRMATION`, and `LEGACY_ONLY` are distinct roles; task units and frozen
   near-duplicate groups cannot cross roles. Profile development may use only `QUAL_DEV`; the single
   integrated acceptance may use one previously unexposed `QUAL_ACCEPT` dataset exactly once;
   discovery and randomized confirmation may use only their respective held-out roles.
7. The semantic `policy_key` is model-independent. A model-specific scientific effect coordinate is
   `(policy_key, model_id)`. A model-bound Stage-II candidate record is dispatched only to its bound
   model; confirmation must not cross it with every configured model a second time.
8. Candidate universes, selector configurations, mappings, realization distributions, outcomes,
   contrasts, multiplicity families, analysis scope, model dispatch, data roles, budget slots, and
   analysis code are frozen before confirmation outcomes exist. Expected direction is not an
   identity coordinate or a ranking orientation.
9. `target_changed`, semantic compliance, and non-target drift remain diagnostics and never filter
   the assigned-arm ITT denominator.
10. A valid terminal no-code, parse failure, functional failure, or Oracle-unknown result remains
   assigned-arm data under its predeclared outcome encoding. Missing or corrupt required evidence is
   an infrastructure/provenance failure and must be repaired or replayed.
11. No outcome-dependent threshold relaxation, candidate replacement, realization replacement,
    extractor selection, Oracle tuning, or favorable reranking is permitted.
12. `K_A`, `K_I`, selector baselines, model sets, task counts, realization counts, block slots, and
    provider ceilings are one joint budget decision. Empty, failed, and non-evaluable slots stay in
    the fixed denominator and cannot be replaced.
13. Discovery-population supplementation is an optional, bounded pre-Discovery preparation step,
    not a fourth scientific stage. It may add only independently sourced natural task units and is
    blind to outcomes, FCI/RD outputs, selector ranks, and Pair relation support.
14. Atomic and Pair discoverability use one outcome-blind Gate family. Pair admission never depends
    on either factor having passed or been selected by the Atomic pipeline; pure interactions remain
    eligible when their own Pair context, compatibility, support, lineage, and fold Gates pass.
15. Context-modifier inference and Pair response-pattern classification are inactive until their
    exact task assignment, multiplicity/bootstrap rules, and deterministic predicates have been
    prospectively frozen. Missing rules produce explicit blocked states, never guessed defaults.

## 4. Two Explicit Data-Generating Regimes

The method has two scientific data-generating regimes—natural discovery and randomized
confirmation—but five immutable data-use roles:

```text
QUAL_DEV       repeatable profile development and debugging only
QUAL_ACCEPT    one previously unexposed, one-shot integrated acceptance only
DISCOVERY      natural-Prompt candidate support and prioritization only
CONFIRMATION   held-out randomized policy-effect estimation only
LEGACY_ONLY    historical verification only; never an input to target-protocol claims
```

Each named dataset has a `data_id`, role, exact sorted `task_unit_id` manifest, source digest, and
task-manifest digest. Each task-unit record additionally binds its near-duplicate group, source
lineage, exposure history, and role-assignment version. A single content-addressed
`DataRoleManifest` records these bindings. A task unit may participate in more than one `QUAL_DEV`
exercise, but it may not cross roles; a near-duplicate group may not cross roles either. The one
`QUAL_ACCEPT` binding must have empty exposure histories when frozen. Every formal runner calls the
shared `validate_data_role_firewall` preflight before reading discovery outcomes, assignments, or
confirmation outcomes. At minimum:

\[
D_{qdev}\cap D_{qaccept}=\varnothing,
\qquad
D_{qual}\cap D_{disc}=\varnothing,
\qquad
D_{qual}\cap D_{confirm}=\varnothing,
\qquad
D_{disc}\cap D_{confirm}=\varnothing.
\]

Here `D_qual=D_qdev\cup D_qaccept`. `LEGACY_ONLY` is disjoint from all four prospective roles.
Qualification is not pilot evidence for the target effect and cannot be promoted to discovery or
confirmation after results are seen. Before `QUAL_ACCEPT` is opened, all candidate profiles,
selection rules, thresholds, tie-breaks, failure behavior, code commit, and the role manifest are
frozen. A failed acceptance sets `qualification_status=BLOCKED`; that dataset becomes exposed and
cannot be reused after any implementation or profile change.

### 4.1 Discovery regime

For semantic task cluster `c`, task instance `i`, model `m`, and request-randomness slot `s`, let
`P_i^0` be the natural, unmanipulated Prompt. Discovery does not require the actionable feature to
be absent: its natural Prompt-side state may be `PRESENT`, `ABSENT`, or `UNRESOLVED`. It may not be
created, removed, or relabeled using generated code or confirmation outcomes. With a run-locked
extractor `E`, define:

\[
T_E(P_i^0)=(V_i^0,E_i^0,\tau_V,\tau_E,\operatorname{attr}),
\qquad
X_{if}^{0}=q_f(T_E(P_i^0)).
\]

The discovery regime is:

\[
W_i\rightarrow P_i^0\rightarrow X_i^0,
\qquad
(P_i^0,M_m,U_{ims})\rightarrow G_{ims}^0\rightarrow Y_{ims}^0.
\]

`W` is approved pre-treatment task metadata, `G` is the generated program artifact, and `Y` is a
committed outcome. The primary local FCI table contains only a minimal non-deterministic subset of
`W`, natural-Prompt queries `X^0`, and discovery outcomes `Y^0`. `G`, raw code, implementation
markers, arm identity, intervention diagnostics, and post-treatment features are excluded.

Discovery, ADD confirmation, and REMOVE confirmation have separate admission rules. Discovery
requires an unmanipulated natural Prompt and within-context feature support. ADD confirmation
requires the target feature to be `ABSENT`. REMOVE confirmation requires it to be `PRESENT` with
provenance-bound evidence and an outcome-blind, task-preserving neutral counterpart. A task unit's
eligibility for one regime does not imply eligibility for either other regime.

### 4.2 Confirmation regime

For a frozen hypothesis `h`, assigned arm `A`, and global realization-specification index `R`, the
intervention executor first resolves the unique task bundle `g_i(R)` bound to `(h,i,R)` and applies:

\[
\Gamma_{h,A,R}(P_i^0)=P_i^{A,R}.
\]

The confirmation regime is:

\[
(P_i^0,A,R)\rightarrow P_i^{A,R},
\qquad
(P_i^{A,R},M_m,U_{ims})\rightarrow G_{ims}^{A,R}
\rightarrow Y_{ims}^{A,R}.
\]

The independently extracted post-intervention projection

\[
X_{if}^{A,R}=q_f(T_E(P_i^{A,R}))
\]

is a treatment-fidelity diagnostic. It is not the randomized treatment and must not be substituted
for assigned arm `A` in the primary effect estimator.

### 4.3 Intervention bridge

The two regimes are joined by an explicit, audited bridge rather than by equating `X^0` and
`X^{A,R}`:

\[
B:\widetilde h=(k_h,\mathcal Q_h)
\longmapsto
\bigl(\text{TargetSpec},\Gamma,Q_h,\text{ArmProtocol}\bigr).
\]

The bridge is finite, catalog-bound, outcome-blind, and frozen before confirmation. A randomized
result confirms the bridged Prompt policy for its declared population and realization distribution;
it does not directly prove an edge in the observational PAG.
Discovery evidence, selector identity, and rank reference the skeleton through selection artifacts;
they do not change bridge behavior or final-hypothesis identity.

Here `k_h` is the model-independent semantic policy key defined in Section 6. Materialization is
deduplicated by the frozen semantic-policy/protocol lineage, while each model-specific effect remains
the separate coordinate `(k_h,m)`. If Stage II ranks the same semantic key for two models, it creates
two model-bound candidate records but confirmation dispatches each record only to its bound model.
The current all-policy-by-all-model cross-product is forbidden for those records because it would
create an unintended `M^2` design.

## 5. Prompt TSG as a Formal Intervention Language

### 5.1 Typed graph

For a Prompt `P`, the extractor-relative Prompt TSG is:

\[
T_E(P)=(V,E,\tau_V,\tau_E,\operatorname{attr}),
\qquad
\tau_V:V\rightarrow\mathcal T_V,
\quad
\tau_E:E\rightarrow\mathcal T_E.
\]

The finite type system separates task operations, data objects, sources, sinks, trust boundaries,
Prompt requirements, safety guards, and presentation controls. The catalog, type functions, query
definitions, extractor policy, and canonicalization rules are content-addressed.

#### Prospective contract-first authority

The post-v4 successor does not let an LLM author the scientific graph directly. For one task, all
catalog queries matching its frozen `(CWE, task_family)` coordinates, together with their actionable
features, are the sole `MechanismDefinition`; no parallel mechanism-definition table is introduced.
For (Q(t)), the complete matching query set, they determine one task-level finite decision scope

\[
S_t=\bigcup_{q\in Q(t)}
\left(\operatorname{required}(q)\cup\operatorname{forbidden}(q)\cup\{f_q\}\right),
\qquad
R_t=\bigcup_{q\in Q(t)}\operatorname{requiredRelations}(q).
\]

Before graph compilation, a `TaskContextContract` bound to the task, natural-Prompt hash, catalog
digest, CWE, task family, and complete ordered query-ID set must assign every member of `S_t` and
`R_t` exactly one of `PRESENT`, `ABSENT`, or `UNRESOLVED`. A `PRESENT` semantic requires an exact evidence occurrence. An omitted semantic or
relation is an invalid contract, not evidence of absence. Every decision also carries a bounded
human-reviewable rationale; absence is never represented by an unexplained empty field. Endpoint
evidence validation is fail-closed: when an annotator claims `PRESENT` but its evidence text and
1-based occurrence cannot be found literally in the source prompt, that annotator's semantic row is
deterministically projected to `UNRESOLVED`, its evidence and attributes are cleared, and the raw
provider response is retained unchanged for audit. This uncertainty remains in Gate C scoring; it is
not retried, repaired by another model call, or filtered from the denominator. Endpoint
state precedence is total: if either endpoint is `ABSENT`, the relation is `ABSENT`; otherwise, if
either endpoint is `UNRESOLVED`, the relation is `UNRESOLVED`; only two `PRESENT` endpoints permit
the relation decision itself to be consulted. This endpoint closure is applied deterministically to
each raw annotation before graph validation, so an LLM cannot override a logically implied relation
state and a redundant relation-state mistake cannot abort the task batch. The unmodified raw response
remains in the artifact for audit. Arms and outcomes are unavailable when
the contract is produced and reviewed.

The provider transport uses a deterministic strict JSON Schema derived from the
frozen task scope. `semantic_decisions` is an object whose required properties are
exactly `S_t`; `relation_decisions` is an object whose required properties encode
exactly `R_t`. Each property has the frozen state/evidence/rationale/attribute value
schema and both objects reject additional properties. This makes omission,
duplication, and scope widening structurally impossible while leaving evidence and
rationale text open. The local parser still verifies the independently derived key
set, exact evidence occurrences, catalog attributes, endpoint closure, consensus,
and graph replay. JSON Object mode or one static row-array schema is insufficient:
neither can require a task-dependent finite identity set.

Task units may be scheduled with a prospectively frozen bounded worker count.
Each task still executes proposer then reviewer in that order, each annotator still
receives the same source-only request and frozen seed, and there is no retry or
winner selection. The artifact is always serialized in frozen selection order,
not completion order. The worker count and effective worker count are recorded in
the extraction report and independently checked against the qualification gold;
therefore bounded concurrency changes wall-clock scheduling, not the estimand,
population, call count, consensus rule, or Gate threshold.

Two LLM calls with different frozen seeds independently complete this finite table from the same
source-only request; neither sees the other's output. State disagreement becomes `UNRESOLVED`.
When both mark a semantic `PRESENT`, a deterministic rule retains the longer already-validated exact
span and only attributes asserted by both. The consensus contract, not either model response, is the
scientific authority. A deterministic compiler derives node types from the catalog, verifies evidence spans and
logical consistency, and emits the Prompt TSG. Record schema 2.0 preserves unresolved relations
explicitly; schema-1.0 identities and frozen runs remain compatible and are never migrated in
place: their canonical field set and content identity are unchanged, and the frozen files are not
rewritten. If the compiled TSG later proves to add no query or intervention behavior beyond this typed
contract, the graph layer must be removed instead of retained as a decorative abstraction.

The initial four-case replay is an exposed architecture canary only. It can show that completeness,
relation uncertainty, and legacy identity preservation work as implemented; it cannot estimate
automatic extraction accuracy or reopen Gate C. Activation requires a new prospectively frozen,
independent qualification of contract production. That Gate evaluates the proposed decision table
against source-only gold and separately reports semantic-state accuracy, relation-state accuracy,
present recall, false-positive present states, and wrong realization identity.

For compatibility with the reusable PromptTSG 2.1 graph schema, `SANITIZER` is not persisted as a new
node type or attribute. The separately versioned query catalog interprets a finite reviewed subset of
existing `GUARD` semantic identities as sanitizing guards and binds that interpretation to the graph
and catalog digests. A future dedicated sanitizer type or attribute requires a new Prompt TSG schema
and an explicit graph migrator under Section 21.

### 5.2 Well-formedness

A graph is publishable only when all of the following hold:

1. every node and edge uses a finite catalog/type identity;
2. every edge endpoint has a type permitted by the edge-type matrix;
3. every source, sink, guard, and sanitizer refers to one bounded task/data-flow context;
4. a guard or sanitizer match is valid only when it is attached to the relevant source-to-sink flow,
   not merely mentioned elsewhere in the Prompt;
5. safety requirements declare applicable CWE and task archetypes;
6. presentation nodes cannot enter task or safety flow motifs;
7. duplicate semantic identities, dangling endpoints, contradictory states, and unbounded traversal
   fail closed; and
8. query and projection results are recomputed from the canonical graph, never from an LLM-authored
   flat shadow; and
9. contract-first graphs enumerate every task-scope semantic and required relation across all matching queries before
   compilation; omission is a schema error, never `ABSENT`.

### 5.3 Four-valued query semantics

Every direct feature or context query has the total function:

\[
q:T_E(P)\rightarrow
\{\textsc{present},\textsc{absent},\textsc{not-applicable},\textsc{unresolved}\}.
\]

- `PRESENT`: at least one complete, type-valid, evidence-backed match exists.
- `ABSENT`: the scope is applicable, every required role is resolved, bounded matching completed,
  and no valid match exists.
- `NOT_APPLICABLE`: the frozen CWE/task-archetype applicability predicate is false.
- `UNRESOLVED`: extraction, evidence, conflict, or bounded matching cannot justify any other state.

For prospective path-access representations after the failed evidence-occurrence v4
qualification, base-directory authority uses an explicit-evidence triage. A base is
`trusted` only when the source prompt explicitly states that it is application-configured,
deployment-fixed, a literal task constant, predefined independently of caller input, or
otherwise not caller-controlled. A base is `caller_supplied` only when the prompt explicitly
places it in a function argument or signature, request field, command-line value, or states
that the caller selects it. Merely listing `base_dir` under `Context`, naming an allowed
directory, or already requesting path confinement establishes neither authority. When the
prompt describes a bounding base but leaves its authority unspecified, both authority
alternatives remain `UNRESOLVED`; when no bounding base is described, both are simply absent.
This is a new prospective representation rule and does not relabel, repair, or reopen the
frozen v4 Gate C result.

The successor implementation represents this triage as one frozen task-side annotation,
not as another free-form LLM judgment. The annotation is bound to `task_id` and
`prompt_sha256`, cites an exact prompt occurrence when a base is described, and has exactly
one of four states:

```text
application_configured | caller_supplied | unspecified | no_bounding_base
```

`unspecified` projects both authority alternatives to `UNRESOLVED`; `no_bounding_base`
projects both as absent. For the other two states, the implementation injects exactly one
evidence-bound authority fact after semantic review. Proposer opinions about these two
authority semantics are removed and disclosed; the reviewer is not offered those semantics,
and an out-of-scope reviewer output fails closed. It continues to judge only source, sink,
feature, and other task semantics. A trusted-base relation is added only
when exactly one `sink.file_access` fact exists; otherwise the trusted-base binding remains
unresolved. When the reviewer accepts a fact already proposed in stage one, its semantic
decision is retained but the already validated proposer evidence span and occurrence are
reused. Newly resolved facts still require new exact evidence. This keeps the LLM responsible
for open-text semantics without asking it twice to locate or infer the frozen authority
coordinate.

An exposed development replay cannot qualify this successor. Before it becomes the active
extractor, the annotation protocol, task population, labels, catalog, model settings, and
thresholds must be frozen on a genuinely independent corpus, and the existing Prompt-TSG
qualification verifier must pass without changing the v4 record. The DevEval v4 freeze and its
tasks are `LEGACY_ONLY` for this protocol: its implementation hashes are verified against the
recorded historical commit, never against or by rewriting current active source.

For existential motifs, multiple matches aggregate to `PRESENT`. A negative condition such as
"without a guard" is satisfied only after the matcher has checked the same bounded flow for a valid
guard. Search exhaustion, traversal bounds, or unresolved endpoints produce `UNRESOLVED`, not
`ABSENT`. A negative condition whose truth depends on the target feature `f` is permitted only in a
legacy or diagnostic query; it cannot define prospective context eligibility.

Context and operation eligibility are total pre-outcome functions. For task instance `i` and
hypothesis `h`, define

\[
s^C_{hi}=q_{C_q}(T_E(P_i^0)),
\qquad
s^f_{hi}=q_f(T_E(P_i^0)).
\]

The context gate passes if and only if `s^C_hi=PRESENT`. `ABSENT`, `NOT_APPLICABLE`, and
`UNRESOLVED` are three distinct typed pre-randomization exclusions; they are never collapsed into a
generic missing row. The operation gate passes only under one of these source-state rules:

- `ADD`: `s^f_hi=ABSENT`, which already entails an applicable, resolved query;
- `REMOVE`: `s^f_hi=PRESENT`, the positive target clause/node has provenance-bound evidence in
  `P_i^0`, and a task-preserving neutral counterpart is attested before variant generation.

The neutral counterpart may remove or neutralize only the positive target requirement. It must not
insert an insecure instruction, request a vulnerable implementation, or change task/context
semantics. Opposite feature states, `NOT_APPLICABLE`, `UNRESOLVED`, missing target evidence, and
failed counterpart attestation receive separate exclusion reasons. The query, source-state rule,
counterpart-attestation policy, exclusion vocabulary, and eligibility-function digest are frozen
before selection. For the selected union, each task-specific evidence binding and neutral-counterpart
record is frozen before variant generation and randomization, without access to code outcomes.
Post-assignment `target_changed` remains a fidelity diagnostic and never redefines this gate.

### 5.4 Context and actionability

The catalog distinguishes three objects:

1. `ContextQuerySpec`: a non-editable task/security context such as untrusted input reaching a shell
   operation;
2. `ActionableFeatureSpec`: exactly one Prompt-side requirement that ADD or REMOVE may edit while
   preserving the task; and
3. `CompositeHypothesisPattern`: a context query mapped to exactly one actionable leaf feature.

A composite pattern with zero or multiple actionable leaves cannot become a randomized hypothesis.
Source, sink, trust boundary, API, task archetype, and data-flow context remain eligibility or
effect-modifier variables; they are never silently edited to make an intervention possible.

`C_q` must be defined independently of the target feature state. A legacy motif such as "source
reaches sink without guard `f`" is not a valid context query because it deterministically mixes the
task context with `f=ABSENT`. The prospective query is split into a guard-independent context such
as "source reaches sink" and the separately queried actionable feature `f`. Existing
`WITHOUT_GUARD` motif identities cannot be relabeled; they require new query IDs and regenerated
causal tables.

Prospective context queries live in a separate versioned catalog identified by
`context_query_catalog_sha256` and `query_semantics_version`. An `ActionableFeatureSpec` is an
immutable reviewed reference or adapter to an existing `FeatureSpec` ID and feature-catalog digest;
it does not mutate the legacy feature catalog or graph digest. Every query result binds the Prompt
TSG digest, context-query-catalog digest, and query-semantics version. Adding a context query
therefore invalidates derived query tables, not a byte-identical compatible Prompt TSG artifact.

### 5.5 Extractor-relative rewrite invariants

For hypothesis `h=(C_q,f,a,Q_h,Y)`, every frozen arm realization must satisfy the arm-specific
AllowedDelta and, where applicable:

\[
\pi_{\mathrm{task}}(T_E(P_i^{A,R}))
=\pi_{\mathrm{task}}(T_E(P_i^0)),
\]

\[
\pi_{C_q}(T_E(P_i^{A,R}))
=\pi_{C_q}(T_E(P_i^0)),
\]

\[
\pi_{\neg f}(T_E(P_i^{A,R}))
=\pi_{\neg f}(T_E(P_i^0)).
\]

These are extractor-relative, finite-catalog invariants. They are auditable operational checks, not
a theorem that two unrestricted natural-language texts are semantically identical.

## 6. Context-Conditioned Hypotheses

### 6.1 Canonical analysis scope

One `AnalysisScope` defines the outcome-blind population on which a policy question is asked:

```text
analysis_scope = {
  security_pattern_id,
  context_query_id,
  language_scope,
  api_scope,
  task_archetype_scope
}
```

Each scope collection is a non-empty, unique, lexicographically sorted finite tuple. These are the
only population fields admitted to the target semantic identity. Selector results, discovery model,
expected direction, rank, score, support status, relation result, compatibility result, and any
post-assignment field are excluded. Adding another scope field requires a prospective protocol
amendment and collision audit; it cannot be inferred from observed effects.

### 6.2 Model-independent semantic policy keys

For one Atomic policy, let `S` denote the canonical analysis scope, `f` one actionable feature,
`a in {ADD,REMOVE}`, and `Y` the pre-registered outcome. Its semantic key is:

\[
k_A=\operatorname{Key}(\texttt{atomic},S,(f,a),Y).
\]

For a Pair policy, attach each operation to its feature, sort the two `(feature,operation)` records
canonically, and define:

\[
k_I=\operatorname{Key}(\texttt{pair},S,
\operatorname{sort}((f_1,a_1),(f_2,a_2)),Y).
\]

Pair input order therefore cannot create a second scientific question. Relation type, relation
support, compatibility result, lane, selector, rank, score, Oracle qualification record, expected
direction, and model are not part of either semantic key. Outcome and analysis scope remain explicit,
so scientifically different populations or endpoints do not collide.

### 6.3 Model effect and protocol-record coordinates

The semantic policy key is shared across models. The effect coordinate is:

\[
e_{h,m}=(k_h,m),
\qquad
\tau_{h,m}.
\]

When Stage II performs model-specific discovery, its immutable record identity is:

```text
candidate_record_id = hash(policy_key, discovery_model_id, protocol_id, schema_version)
```

That record is dispatched only to `discovery_model_id`. A replication model receives its own
prospectively frozen effect-coordinate record; confirmation never loops a model-bound record over
the complete model list. This separates scientific policy reuse from model-specific effects and
prevents accidental `M^2` requests.

The semantic key deliberately excludes realization wording and producer details. Those coordinates
belong to a protocol-bound hypothesis record containing `RealizationPolicySpec`, `TargetSpec`,
executor/extractor policies, arm protocol, and their digests. Two protocol records can refer to the
same semantic question, but they are not pooled or substituted when their intervention distribution
or protocol differs. An effect-coordinate identifier is meaningful only together with its frozen
protocol record.

### 6.4 Bridge and fixed-slot consequences

The shared selector universe contains immutable model-bound candidate records plus their semantic
keys. After selector rankings are frozen, take the unique union of all filled `K_A` or `K_I` slots.
The common selector-invariant bridge protocolizes each unique semantic-policy/protocol record once
and retains a `candidate_to_slots` fan-out. A bridge or protocolization failure leaves every original
slot as zero yield; it cannot mutate the semantic key, record, universe digest, rank, model binding,
or realization policy.

For a successful bridge, task-specific arm texts are materialized as
`TaskRealizationBundleRecord`s that reference the global specification. Neither specifications nor
task bundles are chosen or changed using code-generation outcomes. Reuse across model-effect records
is allowed only through an explicit frozen policy-lineage map; equality of generated text after the
fact is not deduplication authority.

A relational motif can support `C_q`; it cannot itself be assigned. The observation that a motif is
associated with an outcome does not authorize changing its task-context nodes. Only `f` enters the
`TargetSpec` and graph/text rewrite.

Each operation is atomic: `ADD` and `REMOVE` create different semantic keys, candidate-budget slots,
protocols, and multiplicity coordinates. A record that merely lists both operations as permissions
is not yet a confirmable hypothesis. Expected direction may be retained only as a blinded forecast
diagnostic; changing it never changes semantic identity, rank orientation, or inferential status.

## 7. Observational Prioritization

### 7.1 Variable discipline

All simultaneously authored natural-Prompt features occupy the same temporal tier. Unless a separate
Prompt-authoring SCM supplies a justified order, the main analysis:

- does not interpret `X_1 -> X_2` as a security mechanism;
- does not call an `X_1-X_2-Y` path Prompt-feature mediation; and
- prioritizes feature/outcome adjacency, possible ancestry, and context-conditioned relevance.

Redundant direct features, motifs, and deterministic projections are not placed together in one CI
table. Each table publishes a deterministic-dependence audit and the minimal generating variable set
used by FCI.

The primary design uses **family-local FCI tables**, not one repository-wide graph. A frozen
mechanism-family manifest determines the context queries, actionable Prompt features, approved
pre-treatment covariates, measurement-support indicators, and outcome included in each table. Open
task-local TSG evidence remains provenance and cannot become a new causal variable. Every row is one
independent task unit; request slots are aggregated or sampled only under the frozen analysis in
Section 7.4.

Before FCI, each `(C_q,f)` receives an outcome-blind positivity audit within the `C_q=PRESENT`
population. The audit reports `PRESENT`, `ABSENT`, `UNRESOLVED`, and excluded task-unit counts,
source-lineage overlap, and deterministic dependencies. A candidate enters FCI only when both
feature states meet the preregistered minimum independent-task support and neither state is a proxy
for one source lineage. A failed gate is a selector-support result; it cannot be repaired by pooling
unrelated families, smoothing a constant column, or manufacturing feature states through an
intervention and calling them observational.

### 7.2 FCI backend and assumptions

The minimum backend remains pinned `causal-learn` FCI with the G-square CI test and no Java runtime.
Each run freezes alpha, depth, maximum path length, variable/state order, missing-state policy, and
background knowledge. Interpretation is conditional on causal Markov, suitable faithfulness,
adequate CI support, measurement quality, and the declared task population. PAG circles remain
circles.

### 7.3 Candidate relations

For a candidate actionable feature `f` and outcome `Y`, an FCI selector may score:

1. a permitted `X_f^0-Y^0` adjacency;
2. a permitted endpoint-compatible possible-ancestor relation from `X_f^0` to `Y^0`; or
3. the same relation within the predeclared `C_q`-eligible task population.

Candidate extraction does not require an edge, supply a preferred endpoint, or orient
same-tier Prompt variables merely to create a path. Endpoint patterns and PAG uncertainty are preserved in the
frozen evidence.

### 7.4 Three seed/randomness analyses

The discover manifest uses the general name `request_randomness_slot`. A provider-supported numeric
seed is separate provenance and must not be claimed reproducible when the provider does not guarantee
it.

Each selector reports:

1. **fixed-reference analysis:** one pre-outcome reference slot per task, with semantic-task-cluster
   bootstrap;
2. **two-level analysis:** resample semantic task clusters and then select one frozen request slot
   inside each sampled task occurrence; and
3. **multi-slot sensitivity:** aggregate all frozen slots at task level and report variable/outcome
   means and selector-rank stability. If an aggregate causal table is used, its state-preserving
   aggregation rule and CI test must be separately frozen; fractional means must not be passed to
   G-square as categorical states.

The primary stability rule is frozen before discovery. The other two analyses cannot be used after
confirmation to rescue or discard a candidate.

### 7.5 Background-knowledge audit

Every background-knowledge item records:

- its ID and provenance class: temporal order, type system, or reviewed domain knowledge;
- every forbidden direction or adjacency it contributes;
- the affected variables and candidate relations;
- the raw/minimal-BK PAG and the full constrained PAG; and
- whether candidate eligibility or rank changes when the item is removed.

The primary run uses the frozen full typed BK. Sensitivity runs include temporal-only BK, removal of
domain-specific BK families, and at least one wrong-but-plausible BK perturbation. A candidate edge or
path may never be required. If the primary candidate set is determined almost entirely by BK rather
than CI evidence, that dependence is reported rather than hidden.

## 8. Budgeted Selector Evaluation

### 8.1 Formal objective

For a candidate universe `\mathcal H`, model-specific discover data `D_{disc,m}`, and selector
`\ell`, the frozen selector run returns:

\[
S_{\ell m}=\{s_{\ell m1},\ldots,s_{\ell mK}\},
\]

where each slot contains one model-bound candidate record or a typed `EMPTY` value. Every selector
always retains exactly `K` slots; Gate failure, non-evaluable score, bridge failure, and an exhausted
universe never reduce the denominator or trigger replacement.

Its prospective utility is:

\[
U_{\ell m}=
\mathbb E\!\left[
\sum_{k=1}^{K}
I\{s_{\ell mk}\text{ has a meaningful held-out randomized status}\}
\right].
\]

This utility is evaluated after the selector, rank order, and top-`K` slots are frozen. It is not an
objective used to tune FCI on confirm outcomes.

### 8.2 Selector-only comparison

One Atomic `CandidateUniverseManifest` freezes identical semantic keys, model-bound records,
eligibility rules, natural-state rows, candidate-specific folds, outcome, realization-policy
specification, and information budget for exactly two required variants:

```text
Atomic Full     qualified FCI adjacency Gate + shared first-order RD rank
Atomic RD-only  no FCI Gate                  + shared first-order RD rank
```

Both variants use the operation-specific target-minus-baseline probability-scale RD, rank by its
absolute magnitude with one deterministic tie-break, and retain the signed value for interpretation.
They do not use expected direction. An automated sole-difference record proves that only Atomic Full
reads the FCI Gate; universe, support, folds, RD model/score, `K_A`, bridge, model dispatch,
confirmation, and inferential status are otherwise byte-identical.

Pair Full and Pair No-Relation follow the Section 24 sole-difference contract with `K_I`. Optional
blinded Expert and seeded Random baselines enter RQ1 only if the jointly frozen budget qualification
selects the corresponding envelope. They never become silent defaults. Expert cards and Random
seeds are frozen before discovery outcomes are scored; no best random draw is selected.

Selecting an RQ1 comparison envelope creates an implementation obligation, not merely a budget
label. Every listed comparison method or baseline must emit a target-schema selector artifact with
fixed slots, blindness or seed provenance, the same frozen candidate universe, `K`, bridge,
confirmation protocol, status vocabulary, and independent-verifier coverage before the
`DiscoveryDesignFreeze` is written. Legacy association, prediction, expert, or random outputs do not
satisfy this obligation without an explicit target-schema definition and migration. Conversely,
scope control prohibits only methods outside the author-approved RQ1 set; it never permits a required
comparison or selected baseline to be omitted for speed.

Across every approved variant, the union of unique filled slots passes through the bridge once and
is confirmed once per model effect coordinate. A `candidate_to_slots` map fans that single result
back to every referencing slot. Selector overlap can reduce unique confirmation cost but never a
selector's fixed denominator.

Primary selector metrics are:

\[
\operatorname{meaningful\ yield@K}_{\ell m}
=\frac{1}{K}\sum_{k=1}^{K}
I\{s_{\ell mk}\text{ is positive- or negative-meaningful}\},
\]

and the primary RQ2 selector contrast is the descriptive fixed-denominator Full-minus-Ablation
difference. Empty, bridge-failed, protocolization-failed, and non-evaluable slots contribute zero.
Overlap is resolved through the shared candidate result rather than rank-position pairing. A
continuous selector-utility interval is outside the frozen protocol until separately qualified.
Filled-slot precision, protocolization, and failure composition are secondary.
With one frozen discovery role manifest, this is a conditional held-out benchmark claim. A claim about
expected selector performance over arbitrary discovery samples requires repeated outer splits,
cross-fitting, or an independent replication and is outside the minimum main protocol.

### 8.3 Representation comparison

The former direct-versus-direct+context representation comparison is not an active RQ2 track. Its
existing implementation and artifacts are `LEGACY_ONLY`. A future representation study requires a
separate prospective protocol, budget, candidate universes, and confirmation family; it cannot be
reintroduced through an active configuration flag.

### 8.4 Native-system track

External methods may additionally retain their native candidate spaces. Native candidates are frozen
before mapping and pass through the existing
`K -> native -> mapped -> protocol -> randomized -> confirmed` funnel. This measures end-to-end
system compatibility and yield, not pure selector superiority. Mapping coverage remains a bridge
diagnostic.

## 9. Multi-Realization Intervention Policies

### 9.1 Global realization specifications and task bundles

For each hypothesis, freeze:

\[
\mathcal R_h=\{r_1,\ldots,r_{K_R}\},
\qquad
Q_h(r)=q_{hr},
\qquad
\sum_r q_{hr}=1.
\]

One `r` indexes a task-independent `RealizationSpecRecord`, not a task-specific Prompt and not a
favorable target-only wording. The record freezes `realization_spec_id`, `q_{hr}`, every arm's
template or execution policy, matching rules, validation requirements, and executor/extractor
provenance. The primary design uses a uniform `Q_h` unless a nonuniform policy is justified and
frozen before generation. A specification contains no task-specific arm text.

Before task-specific text is materialized, a frozen outcome-blind allocator assigns each eligible
task `i` exactly one realization `r_{hi}` from `Q_h`. The allocation is deterministic from the
policy/task/seed manifest, is balanced or weighted to the frozen `q_{hr}` within predeclared strata,
and is shared across model-effect records. Global realization count therefore affects allocation,
minimum task support, and robustness power; it does not multiply every task into `K_R` request
families.

The bridge materializes exactly one `TaskRealizationBundleRecord(h,i,r_{hi})` for that task-policy
coordinate. It binds `task_unit_id`, `task_instance_id`, `realization_spec_id`, the complete
arm-to-`PromptVariant` mapping, exact texts/digests, and variant-validation evidence. Thus actual text
may differ across tasks while the allocated task population implements the same frozen `Q_h`. The
task bundle does not alter `Q_h` or semantic policy identity.

Every task bundle independently passes provenance, security neutrality, AllowedDelta, context
invariance, task invariance, and length/control matching. A failed task bundle is a pre-randomization
protocolization failure and cannot be replaced after any code outcome exists.

The support of `Q_h` is immutable. A failed global `RealizationSpecRecord` makes the hypothesis
unprotocolizable. A task-specific failure in any required arm excludes that allocated
task-by-hypothesis bundle from every preregistered model before assignment and retains its typed
pre-outcome reason. It is never reassigned to another realization or replaced by another task. Let
`G_{hi}=1` exactly when the frozen context Gate, operation-source Gate, allocated bundle Gate, and
minimum realization-support Gate pass. The eligible `\mathcal P_h^C` contains task units with
`G_{hi}=1`; estimation first averages tasks within their assigned realization and then applies the
original frozen `q_{hr}` weights. If any realization lacks its frozen independent-task support or
the target weighting cannot be evaluated, the effect coordinate is `NON_EVALUABLE` rather than
renormalizing `Q_h`.

This is one common-support population and one realization allocation frozen before arm assignment.
Each context state, operation exclusion, allocated realization, Gate-entry count, Gate-pass task
count, and realization-specific failure is reported. A model-specific availability problem must be
repaired before assignment or retained under predeclared post-assignment failure semantics; it cannot
create a more favorable model-specific population. The implementation may not delete a failed `r`,
rerun the allocator, renormalize `Q_h`, or select favorable realization/task bundles.

### 9.2 Arms

Safety ADD retains:

```text
TARGET_PATCH
NOOP_REWRITE
LENGTH_MATCHED_PLACEBO
GENERIC_SECURITY_REMINDER
```

Safety REMOVE retains:

```text
TARGET_REMOVE
NOOP_RETAIN
LENGTH_MATCHED_SHAM_EDIT
GENERIC_SECURITY_REPLACEMENT
```

Target versus operation-matched no-op is primary. Placebo and generic arms test surface-edit and
generic-security explanations. ADD and REMOVE remain separate policies, hypotheses, multiplicity
coordinates, and evidence; a neutral/positive Prompt pair is never counted twice as independent
evidence.

The unedited source Prompt (`ORIGINAL`) is not an arm in the active primary family. A future study
may add it as a separately frozen practical reference, with its own arm family, power analysis, and
multiplicity plan. It cannot be introduced after examining Target-versus-No-op outcomes, and a
Target-versus-Original contrast cannot replace the operation-matched primary estimand.

## 10. Randomization and Independent Units

The three levels are distinct:

| Level | Definition |
| --- | --- |
| arm-assignment unit | one `request_randomness_slot` inside a frozen block |
| randomized complete block | canonical key below |
| superpopulation independent cluster | `semantic_task_cluster_id` |

The one canonical complete-block key is:

```text
(semantic_task_cluster_id,
 task_instance_id,
 hypothesis_id,
 target_spec_id,
 realization_spec_id,
 task_realization_bundle_id,
 model_id,
 arm_protocol_id)
```

Cluster identity is explicit even though task membership also commits to it. `hypothesis_id`,
`target_spec_id`, and `arm_protocol_id` are all retained as defensive provenance bindings. Mutation of
any coordinate changes the block ID.

The assignment manifest binds semantic cluster, task instance, hypothesis, global realization
specification, task realization bundle, model, arm protocol, variant, request slot, provider seed if
any, generation parameters, and RNG provenance. Arms are balanced inside every feasible complete
block. The task bundle must resolve to the same `(h,i,r)` as the other block coordinates.

The same task unit may appear under multiple hypotheses, models, methods, and task instances, but it
has only one allocated realization within a given policy. These records are dependent. Any simultaneous interval, selector
comparison, cross-model comparison, representation comparison, or overall RQ result resamples the
top-level `semantic_task_cluster_id` and carries all descendant records together.

The task-to-cluster manifest freezes the clustering algorithm/model, normalization policy, thresholds,
manual-adjudication sample and decisions, and content digest. No task unit or near-duplicate group may
cross data roles. Primary point estimates weight task units equally and use frozen
within-cluster task weights. Overall comparisons use a frozen CWE/task-archetype-stratified cluster
resample when multiple strata are combined, preserving each stratum's cluster count.

### 10.1 Randomized-effect identification conditions

For block `b`, request slot `s`, and arm set `\mathcal A_h`, identification requires:

\[
A_{bs}\perp\{Y_{bs}(a,r):a\in\mathcal A_h\}\mid b.
\]

The protocol additionally assumes consistency, positive assignment probability for every arm in a
complete block, and no cross-request interference. Provider cache, rate-limit, load, or temporal
state that could couple requests is controlled by randomized execution order, bounded concurrency,
and recorded request timing/state. Violations become sensitivity or failure records.
`X^{A,R}` cannot be used for adjustment, eligibility, inverse-probability weighting, or ITT
filtering.

The intervention bridge is selector-invariant: once canonical hypothesis `h` exists, every selector
that chooses it references the same `TargetSpec`, rewrite operator, `Q_h`, arm protocol, eligible
population, and analysis manifest.

## 11. Outcomes and Estimands

### 11.1 Outcome decomposition

For every assigned unit define:

\[
Y_C=I(\text{a syntactically valid code candidate is produced}),
\]

\[
Y_E=I(\text{the independent Oracle supports and evaluates that valid code}),
\]

\[
Y_{\mathrm{secure\mbox{-}yield}}
=Y_CY_EI(\text{Oracle label is secure}),
\]

and, when the frozen functional contract is available,

\[
Y_{\mathrm{joint}}
=Y_{\mathrm{secure\mbox{-}yield}}I(\text{functional evaluation passes}).
\]

The paper-facing name of the primary safety outcome is **oracle-evaluable secure-code yield**.
`Y_joint` is the key practical secondary outcome. `Y_C`, `Y_E`, functional pass, Oracle unknown,
terminal no-code, parse failure, and arm-conditional Oracle coverage are reported separately.
Functionality is not a mediator and is not a condition for declaring the primary security-policy
effect. Functional non-inferiority is tested only when separately powered and preregistered.

Outcome status is total and explicit:

- terminal no-code or syntactically invalid code has `Y_C=0`, `Y_E=0`, and a distinct no-code/invalid
  status;
- valid code with a supported secure or insecure Oracle decision has `Y_C=1`, `Y_E=1`;
- valid code with an Oracle coverage or semantic unknown has `Y_C=1`, `Y_E=0` and an unknown status;
  and
- missing, corrupt, or unavailable required producers have no outcome value and require repair or
  deterministic replay of the same assignment manifest.

Arm-conditional Oracle coverage uses valid code as its denominator,
`sum(Y_C Y_E) / sum(Y_C)`, and is reported as not applicable when an arm produces no valid code.
The all-assignment evaluable-code yield `mean(Y_C Y_E)` is reported separately so an arm cannot hide
low code production behind conditional coverage.

The active analysis freeze lists the five endpoints in this exact order: secure yield, code
validity, Oracle evaluability, functionality, and joint success. It also freezes the maximum
per-arm acceptable unknown fraction among valid code. If functionality non-inferiority is declared
separately powered, the freeze must contain a study-specific power qualification binding the
task-unit contrast, planned support, model policy, target power, alpha, margin, method, and
assumptions; otherwise no such qualification or practical-success permission may be present.

### 11.2 Policy estimand

For hypothesis `h` and model `m`, let `\mathcal P_h^C` be the eligible semantic-cluster
superpopulation, `Q_{h,I\mid C}` the frozen distribution of task instances inside a cluster,
`Q_h^R` the realization distribution, and `Q_m^U` the model/request-randomness distribution. Let the
immutable task-bound background `B_{CI}` contain the source Prompt, frozen functional contract,
Prompt-TSG context, and non-target task requirements. The primary target-versus-no-op estimand is:

\[
\tau_{hm}^{Y}
=\mathbb E_{\substack{
C\sim\mathcal P_h^C,\ I\sim Q_{h,I\mid C},\\
R\sim Q_h^R,\ U\sim Q_m^U}}
\left[Y_{CI}(T,R,U;B_{CI})-Y_{CI}(N,R,U;B_{CI})\right].
\]

This is an intervention-policy ITT over a finite, frozen realization distribution. It is not
`do(X_f=1)`, a natural-language-universal feature effect, a mediation effect, or a model-agnostic
effect. Effects are estimated separately by model unless a new cross-model estimand is preregistered.

### 11.3 Block and cluster estimator

The primary design is fully crossed over every frozen realization. For cluster `c`, task instance
`i`, hypothesis `h`, target `t`, global realization `r`, task bundle `g`, model `m`, and arm protocol
`p`, define the same canonical block as `b=(c,i,h,t,r,g,m,p)`. Here `g` is the unique frozen task
bundle resolving `(h,i,r)`. Let `\omega_{hci}` be the frozen within-cluster task weight and
`q_{hr}=Q_h^R(r)`, with both weight sets summing to one. For arm `a` and assigned request-slot set
`\mathcal S_{b,a}`:

\[
\bar Y_{b,a}
=\frac{1}{|\mathcal S_{b,a}|}
\sum_{s\in\mathcal S_{b,a}}Y_{b,a,s}.
\]

The semantic-cluster contribution is:

\[
D_{hmc}^{Y}
=\sum_{i\in\mathcal I_{hc}}\omega_{hci}
\sum_{r\in\mathcal R_h}q_{hr}
\left(\bar Y_{cihrm,T}-\bar Y_{cihrm,N}\right).
\]

With `C_h` eligible semantic clusters:

\[
\widehat\tau_{hm}^Y
=\frac{1}{C_h}\sum_{c=1}^{C_h}D_{hmc}^{Y}.
\]

Under one task per semantic cluster and balanced uniform realizations this reduces to:

\[
\widehat\tau_{hm}^Y
=\frac{1}{B_{hm}}\sum_{b=1}^{B_{hm}}
\left(\bar Y_{b,T}-\bar Y_{b,N}\right).
\]

Here the simplified sum traverses only blocks for fixed `(h,m)`.

Point-estimator weights, cluster definition, minimum support, bootstrap RNG, failed-replicate policy,
and percentile/studentization method are frozen before outcomes. A balanced-incomplete realization
design would require separately approved inclusion probabilities and an IPW estimator; it cannot use
these formulas.

### 11.4 Unknown and coverage sensitivity

The observable primary yield treats unsupported or Oracle-unknown valid code as no observed secure
yield, without relabeling it insecure. To bound latent secure valid-code yield, define:

\[
L=Y_{\mathrm{secure\mbox{-}yield}},
\qquad
U=L+I(Y_C=1,Y_E=0).
\]

For target-minus-no-op, report the Manski-style arm bounds:

\[
\mathbb E[L_T]-\mathbb E[U_N]
\le \tau_{\mathrm{latent\ secure}}
\le
\mathbb E[U_T]-\mathbb E[L_N].
\]

Also report code-valid yield, Oracle support, unknown rate, terminal no-code rate, and coverage by arm,
realization, CWE/task archetype, and model. A security claim may not be attributed to safer code when
the observed contrast is instead explained by differential code production or Oracle support.
Every arm mean and bound uses the same semantic-cluster, within-cluster task, and realization weights
as the primary estimator.

## 12. Multiplicity and Simultaneous Inference

For each paper claim, freeze the unique skeleton union `\widetilde{\mathcal H}_K` occupying any
compared method's top-`K` slots and the successfully bridged randomized-hypothesis union
`\mathcal H_K`. Duplicate method/rank references to the same skeleton/final hypothesis share one
randomized estimate and one test. Empty, bridge-failed, or protocolization-failed slots count as
selector failures in the `K` denominator but create no fabricated hypothesis test and do not remove
any already frozen member of `\mathcal H_K`.

The main paper freezes separate families for: (1) every unique `(h,m)` target-minus-no-op
secure-yield contrast; (2) target-specific placebo/generic contrasts; (3) joint-outcome contrasts;
(4) per-realization, interaction, equivalence, and leave-one-realization-out contrasts; and (5)
pre-registered selector pairwise comparisons. ADD and REMOVE are different `h`. The primary family
spans the pre-registered models used by the main comparative claim; model-specific descriptive
families cannot replace it. In particular:

\[
\mathcal F_{\mathrm{primary}}
=\{(h,m,Y_{\mathrm{secure\mbox{-}yield}},T-N):
h\in\mathcal H_K,\ m\in\mathcal M\}.
\]

Primary confirmation uses a semantic-task-cluster max-|T| bootstrap. For each of `B` frozen
replicates, resample top-level clusters and carry every descendant hypothesis, arm, model, method
reference, task instance, request slot, and realization. Index a family member by `j` and compute its
cluster-based standard error:

\[
\widehat\sigma_j^2
=\frac{1}{C_j(C_j-1)}
\sum_c\left(D_{jc}-\widehat\tau_j\right)^2.
\]

This formula applies to a single frozen CWE/task-archetype stratum. If test coordinate `j` combines
strata `g` with frozen point-estimator weights `\lambda_{jg}` (defaulting to the eligible-cluster
share under equal cluster weighting), define stratum mean `\bar D_{jg}` and use:

\[
\widehat\sigma_{j,\mathrm{strat}}^2
=\sum_g\lambda_{jg}^2
\frac{1}{C_{jg}(C_{jg}-1)}
\sum_{c\in g}(D_{jgc}-\bar D_{jg})^2.
\]

Every bootstrap replicate resamples `C_{jg}` semantic clusters inside each stratum and uses the same
`\lambda_{jg}` in its point estimate and studentization. A pooled coordinate with any stratum below
its frozen minimum support is non-confirmable.

Each replicate recomputes `\widehat\tau_j^{*(b)}` and `\widehat\sigma_j^{*(b)}` and defines:

\[
M_b=\max_{j\in\mathcal F_{\mathrm{primary}}}
\left|\frac{\widehat\tau_j^{*(b)}-\widehat\tau_j}
{\widehat\sigma_j^{*(b)}}\right|.
\]

With the frozen quantile/interpolation rule, `q_{1-alpha}` of `M_b` yields simultaneous intervals
`\widehat\tau_j +/- q_{1-alpha}\widehat\sigma_j`. Zero standard error, excessive invalid replicates,
or insufficient cluster support fails confirmation rather than falling back to unadjusted evidence.
The bootstrap count, centering, studentization, interpolation, minimum valid fraction, and family are
simulation-validated and frozen before confirmation. Unadjusted intervals and FDR-adjusted
exploratory results may be reported but cannot replace this rule.

Each unique Atomic effect coordinate receives exactly one of five statuses from its simultaneous
two-sided interval `[L_{hm},U_{hm}]`, frozen practical margin `epsilon_A >= 0`, support, and
provenance:

```text
POSITIVE_MEANINGFUL  L_hm >  epsilon_A
NEGATIVE_MEANINGFUL  U_hm < -epsilon_A
PRACTICALLY_NULL     -epsilon_A <= L_hm and U_hm <= epsilon_A
INCONCLUSIVE         valid evidence not satisfying any preceding interval rule
NON_EVALUABLE        invalid/missing provenance, support, or bootstrap family
```

Pair interaction uses the same vocabulary with `epsilon_I`; its sign is reported as positive or
negative interaction and is not automatically renamed synergy or antagonism. Exact boundary
operators, `epsilon_A`, `epsilon_I`, alpha, and multiplicity families remain qualification-blocked
until the prospective power-and-margin memo is frozen.

Selector ranks and slots remain fixed from the single discovery split. Let `Z_{hm}=1` only for
`POSITIVE_MEANINGFUL` or `NEGATIVE_MEANINGFUL`, and zero for every other status or empty/failed slot:

\[
\widehat U_{\ell m}(K)=\frac{1}{K}\sum_{k=1}^{K}
Z_{\eta(\ell,m,k),m}.
\]

The frozen slot map `\eta(\ell,m,k)` references the one shared effect record; it does not pair
candidates by rank position. RQ2 reports the Full-minus-Ablation `Yield@K` point difference as a
descriptive, fixed-discovery-split comparison. No nested selector-utility confidence interval is
claim-bearing in the minimum protocol. Discovery-split variability and status composition are
reported separately.

No hypothesis-specific effects are pooled into an ATE merely to obtain a smaller standard error.

## 13. Realization and Model Robustness

The overall `Q_h`-average effect remains valid even when realization effects differ. A stronger
`realization-robust` label is awarded only when all preregistered conditions hold:

\[
\tau_{hmr}^{Y}=\mathbb E_{C,I,U}
\left[Y(T,r,U)-Y(N,r,U)\right],
\qquad
\tau_{hm}^{Y}=\sum_rq_{hr}\tau_{hmr}^{Y},
\]

\[
H_{hm}=\max_r\left|\tau_{hmr}^{Y}-\tau_{hm}^{Y}\right|,
\]

and, after omitting realization `r`,

\[
\tau_{hm}^{(-r)}
=\sum_{r'\ne r}\frac{q_{hr'}}{1-q_{hr}}\tau_{hmr'}^{Y}.
\]

1. `K_R` and minimum independent semantic-cluster support per realization were frozen;
2. every realization-specific point estimate and status is reported without direction filtering;
3. the pre-registered sign-consistency proportion relative to the `Q_h`-average estimate is met; the
   strong label requires every evaluable realization to agree in sign;
4. the simultaneous one-sided upper bound on
   `max_r |tau_{hmr}-tau_{hm}|` does not exceed a frozen practical-equivalence margin `delta_h`;
5. the arm-by-realization interaction statistic and its semantic-cluster randomization reference
   distribution are reported; and
6. every leave-one-realization-out policy estimate retains the same positive- or
   negative-meaningful status as the `Q_h`-average estimate.

Across every randomized `(h,m)`, all `K_R` realization-specific contrasts, all `K_R`
leave-one-realization-out contrasts, interaction statistics, and heterogeneity-equivalence
assessments belong to one frozen global robustness family with semantic-cluster max-|T|
simultaneous inference. A separate within-hypothesis descriptive family may be shown but cannot award
the realization-robust label. Point-direction agreement alone supports only a
direction-consistency diagnostic, not the realization-robust evidence level.

If only the average is supported, report: "effective on average under the frozen `Q_h`, with
realization heterogeneity." Do not generalize to all phrasings.

Cross-model replication is a separate label. Per-model effects remain separate; agreement across a
pre-registered proportion of models may support replication but does not create a pooled universal
model effect.

## 14. Optional Implementation Markers

A versioned, outcome-blind code analyzer may produce a finite
`CodeImplementationMarker` such as whether a parameterized query or safe subprocess pattern appears.
Its producer, rules/model, code digest, and calibration are separated from the Oracle producer.

Randomization permits the descriptive assignment effect:

\[
\Delta_h^Z=\mathbb E[Z\mid A=T]-\mathbb E[Z\mid A=N].
\]

This estimates whether assignment changes an implementation marker. It does not identify
`Z -> Y`, a natural indirect effect, a controlled direct effect, complete mediation, or causal
necessity/sufficiency. Markers do not enter the main observational PAG, candidate selection,
eligibility, or primary confirmation status. They may provide triangulating implementation evidence
only when provenance and joint measurement-error calibration are complete.

## 15. Evidence Levels

Every artifact and paper-facing table cell states one engineering/evidence maturity:

1. **Specified:** the prospective contract exists, but implementation or qualification is incomplete.
2. **Implemented:** the active-schema function and artifact fields exist.
3. **Tested:** scientific invariants and independent tamper checks pass in a supported environment.
4. **Executed:** the exact frozen command produced a verified run artifact.
5. **Reported:** a table/claim builder maps that verified artifact into the paper.

These labels are cumulative provenance states, not scientific-effect results. A unit test cannot
promote an artifact to `Executed`, and a smoke, demo, calibration, or development canary cannot be
promoted to confirmatory evidence.

Scientific labels remain separate:

- **Observational Candidate:** frozen discovery evidence under one declared selector; not a causal
  confirmation.
- **Randomized Policy Effect:** one of the five Section 12 statuses from assigned-arm task-unit ITT
  for the declared `Q_h`, model, population, and outcome.
- **Target-Specific Policy Effect:** a meaningful target-versus-no-op status plus the preregistered
  placebo/generic specificity contrasts when that arm family applies.
- **Realization-Robust Policy Effect:** a meaningful average-policy status plus every Section 13
  condition.
- **Cross-Model Replication:** separate model-specific effect coordinates meet the frozen replication
  rule; no pooled universal-model effect is implied.
- **Bidirectional Evidence:** separately randomized ADD and REMOVE policies have prospectively
  interpretable opposite signed statuses; this is not mediation.

Treatment fidelity, implementation markers, per-protocol analyses, JCI, and RFCI cannot promote an
evidence level.

## 16. Main-Paper Research Questions

The main paper contains four concise RQs. Operational details belong in the methods and evaluation
sections rather than the RQ sentences.

> **RQ1. How effectively can different methods prioritize prompt interventions that generalize to
> held-out tasks?**

RQ1's primary comparison is the jointly budget-qualified shared-universe selector set. Core contains
Atomic Full/RD-only and Pair Full/No-Relation. Expert and Random enter only if the frozen RQ1 budget
selects their envelope. Native-system funnels are secondary end-to-end evidence.

> **RQ2. Do the frozen structural Gates improve fixed-budget intervention selection beyond the
> shared observational risk-difference rankings?**

RQ2a compares Atomic Full with RD-only; RQ2b compares Pair Full with No-Relation. Each is a
sole-difference, fixed-`K`, shared-confirmation comparison and reports descriptive meaningful
`Yield@K`, overlap, empty/failure composition, and the complete candidate-to-confirmation funnel.
The former representation comparison is not part of active RQ2.

> **RQ3. Which prompt-side security interventions reliably improve secure code generation?**

RQ3 reports context-conditioned, model-specific, multi-realization policy effects on
oracle-evaluable secure-code yield, with joint functionality and specificity evidence.

> **RQ4. How do security experts rate and rank the perceived quality and usefulness of explanations
> produced by different methods?**

RQ4 is a separately governed human study of perceived explanation utility. It does not measure
objective mechanism identification, code repair accuracy, or the validity of RQ1--RQ3 causal claims.

No RQ claims recovery of a unique Prompt mechanism, universal natural-language feature effects,
code-side mediation, or individual causal flips.

## 17. JCI, RFCI, and Expert Study Scope

Qualified FCI adjacency is only the Atomic Full structural Gate; randomized ITT remains the source
of policy-effect evidence. JCI is retained only as an exploratory appendix analysis of randomized
contexts; it cannot affect candidate selection, rank, assignment, outcome, ITT, or evidence. RFCI
remains an optional appendix sensitivity backend and never blocks the minimum pipeline.

A blinded selector Expert baseline is distinct from RQ4's explanation-perception study and is
included only when named by the frozen RQ1 budget. It receives the same policy cards and permissible
discovery evidence as its comparison track, never confirmation outcomes.

RQ4 remains in the main paper but outside the computational causal-evidence path. It retains its own
ethics determination, preregistration, participant and case manifests, blinded presentation,
randomization, and analysis plan. Its results concern perceived explanation utility only and do not
validate causal discovery, randomized security effects, or objective repair accuracy.

## 18. Artifacts and Provenance

The prospective protocol adds immutable artifacts for:

- `ContextQuerySpec`, `ActionableFeatureSpec`, and composite mapping;
- canonical `AnalysisScope`, Atomic/Pair semantic policy keys, model effect coordinates, and
  protocol-bound candidate records;
- data-role bindings/manifests and qualification-data identities;
- `RealizationPolicySpec`, `CandidateUniverseManifest`, candidate-specific fold manifests, qualified
  FCI/RD/relation profiles, and fixed selector-slot manifests;
- `InterventionBridgeRecord`;
- `SelectionFreezeManifest`, finite `RealizationSpecRecord`s, task-specific
  `TaskRealizationBundleRecord`s, and instantiated `Q_h`;
- semantic-task-cluster membership;
- target `3.x` randomization blocks, model-bound dispatch, and request-randomness slots;
- decomposed outcomes and coverage/bound manifests;
- cluster-bootstrap and simultaneous-inference draws;
- background-knowledge derivation and sensitivity deltas; and
- optional implementation-marker effects with separate provenance.

### 18.1 `DiscoveryDesignFreeze`

The first immutable freeze is written before any formal discovery outcome is read. It contains:

- the `DataRoleManifest` ID, accepted `qualification_bundle` ID, and
  `identity_and_scope_decision` ID;
- the candidate-universe construction contract, support Gates, and candidate-specific fold
  manifests;
- the sole-difference Atomic Full/RD-only and Pair Full/No-Relation selector contracts, fixed
  `K_A`/`K_I`, qualified optional RQ1 baseline set, tie-break rules, and failure semantics;
- the RQ2 comparison semantic `descriptive_fixed_denominator_full_minus_ablation_no_interval`,
  which rejects rank pairing and any continuous selector-utility interval in the target freeze;
- exact model strata, model-bound dispatch, discovery outcome definition, approved pre-Prompt
  covariates, missing/unresolved handling, and all implementation/configuration digests; and
- the accepted RQ1 budget qualification, including task counts, global realization policy, total
  block slots, provider ceilings, and the no-`M^2` preflight. Every provider call kind binds one
  currency, deployment region, named pricing tier and tier input boundary, maximum input/output
  tokens, input/output microunit prices per million tokens, and a frozen pricing reference. Its
  maximum per-call cost is the ceiling of the two token-price products divided by one million;
  the stored rate and independent verifier must both replay that value. All call kinds use one
  budget currency, and a mixed-provider materialization class uses a conservative bound covering
  every call in that class.

It contains no selected slots, ranks computed from formal outcomes, selected union, bridge result,
or confirmation assignment. Candidate-specific folds are outcome-blind and are frozen here before
their discovery scores are computed.

### 18.2 `ConfirmationFreeze`

The second immutable freeze is written after formal discovery has produced its fixed slots, but
before any confirmation outcome exists. It contains:

- every Full/Ablation/baseline slot, including typed empty and failure slots, the unique candidate
  union, and exact `candidate_to_slots` fan-out;
- each semantic policy key, model effect coordinate, protocol-bound record, bridge result,
  protocolization result, and semantic-policy-to-protocol lineage;
- eligible task units and their support/attestation evidence, global realization specifications,
  the exact one-realization-per-task allocation, materialized task bundles, and no-reallocation
  policy;
- complete model-bound randomization assignments, block keys, request-randomness slots, nullable
  provider seeds, arm/cell variants, RNG/balance rules, request order, and model parameters; and
- outcome definitions, assigned-arm task-unit ITT estimands, unknown/bound rules, multiplicity
  families, bootstrap/inference configuration, practical margins, five-status rules, robustness
  analyses, and reporting/table contracts.

It contains outcome *definitions* but no observed confirmation outcomes. A lightweight
`study_freeze_index.json` references `DiscoveryDesignFreeze` and `ConfirmationFreeze` by ID and
SHA-256; it does not merge their timing semantics into a third protocol.

Every join is exact and content-addressed. Discovery producers cannot read confirm manifests.
Extractor, bridge, intervention executor, code generator, Oracle, functional evaluator, marker
producer, and analyst are separately identified. Secrets are never persisted.

## 19. Prospective Sample-Size and Data Gate

No Stage-II or Stage-III tuning parameter becomes active merely because it appears in code or this
draft. Each accepted profile cites a `qualification_data_id` and exact task-manifest digest from the
Section 4 role manifest. The FCI profile freezes backend/version, CI test, alpha, encoding, allowed
`W`, missing/unresolved policy, typed background knowledge, bootstrap count/seed, valid-draw rule,
minimum valid fraction, adjacency threshold, and software digest. Atomic and Pair RD profiles freeze
fold count, candidate-specific outcome-blind fold construction, model family, regularization,
covariates, training-only preprocessing, fit-failure policy, cross-fitting seed, support, bootstrap,
and tie-break rules. The relation profile freezes the four executable predicates, aggregation,
minimum resolved tasks/support, maximum unresolved fraction, and labelled qualification evidence.

`QUAL_DEV`, `QUAL_ACCEPT`, discovery, and confirmation task units remain disjoint. Candidate
profiles may be developed repeatedly on `QUAL_DEV`, but all six selected profile plans—including
the RQ1 baseline-set profile—are sealed together before the one-shot integrated `QUAL_ACCEPT` run.
The baseline profile binds the selected envelope, every track/model coordinate, blinded Expert
information contract or seeded-Random provenance, fixed-slot artifact, and independent replay
receipt. A fold manifest is frozen before the
corresponding discovery outcome score is computed. A candidate whose frozen folds or support are
inadequate is `NON_EVALUABLE`; the implementation never retries another fold count or seed after
observing its score.

The final CWE set, `K`, number of semantic clusters, request slots, models, and `K_R` are frozen only
after simulation under plausible:

- baseline secure yield and functional pass rates;
- semantic-cluster intraclass dependence;
- request-randomness variation;
- realization heterogeneity;
- Oracle-unknown and terminal-no-code rates;
- target effect sizes; and
- the complete multiplicity/selector-comparison procedure.

The primary study should prefer three to four CWE families with executable functional contracts,
sufficient distinct semantic task clusters, and calibrated Oracle support over shallow coverage of
many sparse CWEs. Discovery and confirmation tasks are split by task unit, not row or near-duplicate
Prompt. Simulation code, assumptions, seeds, curves, and the selected design are frozen before the
main run.

RQ1 baseline choice, `K_A`, `K_I`, models, task counts, realizations, and total block slots are one
joint budget decision. Before choosing among them, the budget qualification reports three
worst-case envelopes:

```text
Core                    Atomic Full + RD-only; Pair Full + No-Relation
Core + Expert           Core plus one blinded expert baseline per approved track
Core + Expert + Random  the preceding variants plus seeded random
```

For `c in {2,3,4}` variants per track, `M` model-bound effect strata, and no assumed selector
overlap:

\[
U_A\le c M K_A,
\qquad
U_I\le c M K_I.
\]

With uniform task counts `T`, realizations `R`, and total four-arm/cell block slots `Q`, the
generation-call upper bound is:

\[
N_{gen}\le cM(K_AT_AQ_A+K_IT_IQ_I).
\]

Each task is assigned one frozen realization draw rather than automatically running all
realizations. Independent task units take priority over additional request slots in the power
design. The conservative external-call reservation includes two materialization calls per unique
task-policy-realization bundle, one generation call per assignment, and at most one functional-judge
call per assignment. The local Security Oracle is not counted as a provider call. The preflight
rejects both budget overflow and any configuration that would cross model-bound records with all
models again, even if that erroneous `M^2` design fits the financial ceiling.

The active prospective dataset design, source-lineage constraints, admission contract, replication
boundaries, and freeze sequence are specified in
[`docs/research-dataset-spec.md`](../../research-dataset-spec.md). Its counts are design targets until
the gates in this section and that document produce a frozen task manifest. In particular, the
planned 296 clusters belong to three inferentially separate layers, and the final assignment count is
derived from the frozen hypothesis-specific eligible populations rather than from the task count
alone.

## 20. Failure and Negative-Result Semantics

- Sparse or degenerate G-square support produces a typed discovery failure, not smoothing or a
  post-hoc CI-test substitution in the primary analysis.
- No stable FCI candidate is a valid result and does not authorize lowering stability thresholds.
- A selector that fills fewer than `K` slots retains empty-slot failures.
- An unprotocolizable motif remains a context candidate and does not receive an improvised target.
- Realization disagreement remains reported and prevents only the robustness label, not the frozen
  average-policy estimator.
- Differential Oracle support remains visible through decomposed outcomes and bounds.
- A baseline outperforming FCI is reported under the frozen comparison; it cannot be removed after
  unblinding.
- Optional JCI/RFCI/marker failures do not alter primary FCI or randomized ITT evidence.

## 21. Versioned Migration Boundary

Implementation must add new schema versions rather than mutate legacy content-addressed records.
At minimum, new or upgraded contracts are required for:

1. canonical analysis scopes, semantic policy keys, model effect coordinates, protocol-bound
   candidate records, realization-policy specs, frozen hypotheses, and the intervention bridge;
2. data-role bindings/manifests, candidate universes, selector ranks, candidate-to-slots maps, and
   semantic-policy-to-protocol selection freezes;
3. global realization specifications and task-specific realization bundles;
4. experimental units, block IDs, assignments, and randomization manifests;
5. semantic task-cluster manifests;
6. decomposed assignment outcomes and estimands;
7. discovery and confirm bootstrap manifests; and
8. background-knowledge audits.

The coordinate migration also requires new versions of natural causal observations, generation
requests/results, generated-code records, Oracle/functional/marker records, and assignment outcomes.
They must carry the appropriate `regime_id`, `semantic_task_cluster_id`,
`request_randomness_slot`, `realization_spec_id`, `task_realization_bundle_id`, and nullable
`provider_seed`. Existing required `seed_id` fields cannot be reinterpreted as request slots or made
nullable inside a shared v1 validator.

Keep existing v1/v2 classes and readers intact for historical interpretation. The target `3.x`
schema adds semantically independent identity, role, selection, dispatch, and stage fingerprints.
Any allowed migration is an explicit pure function that records source-artifact and migration-rule
digests. New stages and run directories never overwrite legacy output. A legacy artifact may verify
under its own reader but is rejected by every target-protocol report builder.

The target result index is one exact schema-3.0 bundle. It contains the five-role manifest, accepted
RQ1 budget, discovery design freeze, fixed-slot ledger, shared union and dispatch, the frozen target
randomization plan, model-invariant task-policy bundles, canonical assignments, formal budget
preflight, confirmation freeze and study index, shared assigned-arm evidence, fixed-slot Yield result,
formal report authorization or explicit null, RQ tables, and an independent verification receipt.
Its read-only target verifier must reject missing or extra files, strictly reconstruct every typed
record, and independently replay policy-level protocolization reuse, deterministic complete-block arm
order, variant digests, provider seeds, and all downstream scientific fields rather than trusting the
stored receipt. A claim-authorized index does not replace its referenced raw responses,
measurement artifacts, execution environment, command, provider ledger, or frozen input bundles;
those exact referenced artifacts must accompany the reviewer distribution and clean reproduction.

Legacy Prompt TSG/extraction artifacts may be reused only when task, Prompt, extractor, catalog,
schema, and policy digests remain exactly compatible. Natural-Prompt queries, causal tables,
hypothesis freezes, variants, assignments, outcomes, and analyses must be regenerated under the new
protocol. Old results remain in their original directories and must never be overwritten or silently
upgraded.

Exact natural-Prompt generation and Oracle/functional records may be reassembled into a new
discovery table only when every new coordinate and producer digest can be authenticated. Legacy
confirmation results cannot be upgraded into multi-realization evidence because `Q_h`, global
realization specifications, task realization bundles, common-support eligibility, and assignments
were not frozen before those outcomes; they
remain pilot/exploratory evidence or inputs to prospective power simulation.

The legacy `WITHOUT_GUARD` motif implementation is not a prospective `ContextQuerySpec`: it combines
a guard-independent flow context with the target feature's absence. Compatible canonical Prompt TSG
records may be re-queried, but old motif columns, path freezes, and hypotheses are invalid under the
new context/actionable split. Legacy hypotheses that combine ADD and REMOVE permissions also cannot
be migrated into one atomic v3 hypothesis.

## 22. Acceptance Criteria

The revised framework may move from `SPECIFIED_DRAFT` to `FROZEN` only when tests, independent
verification, qualification artifacts, and spec audits prove:

1. canonical scope and Atomic/Pair semantic keys replay exactly; direction, relation, compatibility,
   rank, score, and model cannot enter the semantic key;
2. model effects are `(policy_key,model_id)`, model-bound records dispatch exactly once, and a
   deliberate model-square configuration fails preflight;
3. every `QUAL_DEV`, `QUAL_ACCEPT`, discovery, confirmation, and legacy dataset has an immutable
   role binding; `QUAL_ACCEPT` is unexposed at freeze and one-shot; task-unit and near-duplicate
   overlaps across roles fail before outcomes are loaded;
4. discovery `X^0`, randomized arm `A`, and diagnostic `X^{A,R}` cannot be conflated in schemas or
   estimators;
5. every confirmable motif maps one context query to exactly one Atomic target; Pair factors remain
   independently editable and canonically ordered;
6. discovery accepts only natural unmanipulated states; ADD and REMOVE use their respective frozen
   source-state and neutral-counterpart rules;
7. Atomic Full/RD-only share universe, support, fold manifest, RD score, tie-break, `K_A`, bridge,
   confirmation, and status; only Full reads the qualified FCI Gate;
8. Pair compatibility creates one common universe; Pair Full/No-Relation share rows, folds, RD score,
   tie-break, and `K_I`; only Full reads relation support;
9. failed FCI draws alter valid fraction rather than adjacency count, and inadequate valid fraction
   produces `NON_EVALUABLE` without threshold relaxation;
10. fixed Atomic and Pair slot ledgers retain empty/failure slots, while the union and
    `candidate_to_slots` map confirm each unique model effect once;
11. the RQ1 Core, +Expert, and +Random budget envelopes replay exactly, and formal preflight rejects
    any unqualified dimension or provider-ceiling overflow;
12. global realization specification, task bundle, model effect, request slot, task instance, and
    task unit are explicit; mutation of any block coordinate changes its block ID;
13. assigned-arm deduplicated-task-unit ITT retains every assignment and preserves code validity,
    Oracle evaluability, secure yield, unknown coverage, functionality, and joint success separately;
14. independent inference reproduces simultaneous intervals and all five Atomic/Pair statuses,
    including exact margin boundaries and non-evaluable rules;
15. all descendants of one task unit resample together, and cross-realization/cross-model labels fail
    when any frozen robustness condition fails;
16. existing v1/v2 artifacts remain verifiable only under legacy readers, never enter target reports,
    and no migrator overwrites a frozen run;
17. JCI, RFCI, implementation markers, fidelity, semantic compliance, generation success, and
    per-protocol diagnostics cannot change primary evidence or denominators;
18. one reviewer smoke run, one clean frozen reproduction, the independent result verifier, RQ table
    builders, and a reading guide of at most ten core files agree on the single seven-stage path.
19. a qualified representation profile precedes the D0 census; the four D0 records bind source,
    retrieval, exposure, deduplication, role, budget, lineage, stopping, code, and verifier evidence,
    and validators reject selector/outcome reads, synthetic tasks, and a second round;
20. the post-census population digest is identical in `DiscoveryDesignFreeze`, Atomic and Pair
    universes, and both discoverability/fold freezes; `COVERAGE_BLOCKED` cannot enter Discovery;
21. every Atomic and Pair candidate receives one typed discoverability decision, and a pure-
    interaction fixture proves that Pair support, folds, RD and selection read no Atomic result;
22. context modifiers remain `BLOCKED_NO_FROZEN_CONTEXT_RULE` with no table until exact task
    assignment, support, joint bootstrap and multiplicity rules are frozen and independently
    implemented; and
23. every Pair result retains an independently reconstructed four-cell response surface while an
    absent rule set produces `BLOCKED_NO_FROZEN_PREDICATE` and a null label; Atomic effects are
    explicitly `NOT_APPLICABLE`.

## 23. Conflict-and-Decision Ledger

| Material claim | Previous authority | Revised action |
| --- | --- | --- |
| one `X` across discovery and confirmation | 2026-07-13 spec | replace with `X^0`, randomized `A`, diagnostic `X^{A,R}`, and an audited bridge |
| relational motif may start a directly editable candidate | 2026-07-13 spec | motif defines `C_q`; only one actionable leaf `f` enters `TargetSpec` |
| secure-and-functional is the primary safety outcome | both previous specs | primary becomes oracle-evaluable secure-code yield; joint remains key secondary |
| block omits realization | 2026-07-13 spec | v2 block includes cluster, task, hypothesis, target, global realization, task bundle, model, and arm protocol |
| task ID is the bootstrap cluster | both previous specs | explicit `semantic_task_cluster_id` is the highest resampling unit |
| seed denotes provider-reproducible randomness | legacy schema wording | use `request_randomness_slot`; provider seed is separate provenance |
| native-method funnel is the main selector comparison | 2026-07-22 spec | shared-universe selector track is primary; native funnel remains secondary |
| two-by-two representation/association table mixes questions | 2026-07-22 spec | separate selector-only and representation-universe experiments |
| JCI is a main method subsection | both previous specs/manuscript | appendix exploratory analysis only |
| RFCI appears in the main method | both previous specs/manuscript | appendix sensitivity backend only |
| RQ4 is a main-paper RQ | 2026-07-22 spec | retain as a separately governed perceived-utility study without causal or repair promotion |
| code markers are forbidden from every analysis | 2026-07-13 spec | permit separately produced post-assignment diagnostics, never primary PAG or mediation |
| raw `PRESENT` always denotes the association target | implementation draft | encode target state by operation: ADD targets `PRESENT`, REMOVE targets `ABSENT` |
| add an unedited Original arm to improve the current result | post-result design discussion | keep Target versus operation-matched No-op primary; Original requires a new prospective arm-family freeze |
| every statistically supported pair is mechanism synergy | pairwise draft | freeze `policy_only` or `mechanism_eligible` per pair and report the narrower supported claim |
| response surfaces receive mechanism names automatically | pairwise draft | use neutral paper-facing response-pattern labels; named mechanisms require independent evidence |
| candidate identity may absorb `model_id` | Phase 0 author decision, 2026-08-31 | semantic `policy_key` is model-independent; the effect coordinate is `(policy_key, model_id)` and a model-bound candidate record is dispatched exactly once |
| scope coordinates are distributed across metadata | Phase 0 author decision, 2026-08-31 | canonical `AnalysisScope` contains security pattern, context query, sorted language/API/archetype scopes, and no selector or outcome-derived fields |
| pilot/discovery/confirm partitions are sufficient for tuning | Phase 0 author decision plus qualification review, 2026-08-31 | use named `QUAL_DEV`, one-shot `QUAL_ACCEPT`, `DISCOVERY`, `CONFIRMATION`, and `LEGACY_ONLY` roles with task-unit, exposure-history, and near-duplicate firewalls |
| one pre-confirmation object can freeze both design and selected hypotheses | qualification review, 2026-08-31 | use `DiscoveryDesignFreeze` before formal discovery outcomes and `ConfirmationFreeze` after fixed slots but before confirmation outcomes; index both by ID and SHA-256 |
| RQ1 baselines and `K` can be selected independently | Phase 0 author decision, 2026-08-31 | compare Core, Core+Expert, and Core+Expert+Random worst-case envelopes first; exact baseline set, `K_A`, `K_I`, models, tasks, realizations, slots, margins, and provider cap remain qualification-blocked |

This ledger is prospective. It does not relabel or reinterpret completed legacy experiments.

## 24. Pairwise Factorial Extension

### 24.1 Scope and non-retroactivity

This section prospectively extends the single-feature policy framework to test the joint behavior of
two atomic actionable Prompt features. It applies only to studies whose freeze explicitly declares
this extension and whose generated-code outcomes do not exist when the freeze is committed. It does
not reinterpret any completed ADD/REMOVE or `ABSENT/SPECIFIC/GENERIC/PLACEBO` study.

The pairwise extension is one additional policy family inside the same seven-stage method. It does
not introduce a second representation, measurement path, Oracle, outcome ledger, or reporting
framework. Sections 3, 5, 10, 11, 12, 18, 20, and 21 continue to apply unless this section states a
strictly more specific pairwise rule.

### 24.2 Pair hypothesis and structural prior

Let `f_1` and `f_2` be distinct catalog-bound atomic actionable features, with operations
`a_1,a_2 in {ADD,REMOVE}`. A confirmable pair is:

\[
k_{12}=\operatorname{Key}(\texttt{pair},S_{12},
\operatorname{sort}((f_1,a_1),(f_2,a_2)),Y),
\]

where `S_{12}` contains the target-state-independent pair context query and the remaining canonical
Section 6 scope fields. `k_{12}` is model-independent and factor input order is not identity. The
model effect is `(k_{12},m)`. A protocol-bound pair hypothesis additionally freezes the finite
joint-realization distribution `Q_{12}`, the risk-difference interaction scale, target specifications,
Oracle profile, compatibility evidence, relation evidence, and all producer digests. Those protocol
and eligibility coordinates do not alter `k_{12}`.

The permitted structural relation vocabulary is finite:

```text
SAME_FLOW
SHARED_SINK
DISTINCT_CONTROL_POINTS
ALTERNATIVE_CONTROLS
```

These labels describe Prompt-TSG task/security structure. `SYNERGY`, `REDUNDANCY`, `PREREQUISITE`,
and `ANTAGONISM` are forbidden as pre-treatment TSG facts or pair-selector inputs; they are possible
post-randomization interpretations. The method requires structural priors in the feature catalog,
pair context query, relation vocabulary, source-state rule, and Oracle profile. It does not require
an expert prior on the sign of the interaction, and the primary interaction test is two-sided.

Composite actionable features must be decomposed before pair admission. A factor is not atomic when
its Target operation necessarily changes the other factor. In particular, SQL value
parameterization and SQL identifier allow-listing, and structured argument-vector construction and
executable allow-listing, are separate atomic factors.

Factorial compatibility is evaluated independently of relation support and freezes one decision from
`COMPATIBLE`, `NESTED`, `MUTUALLY_EXCLUSIVE`, `ENTAILMENT_COLLAPSE`, `CONFLICTING`, or `UNRESOLVED`.
Only `COMPATIBLE` pairs enter the common Pair universe. The No-Relation selector ranks every pair in
that universe that passes shared support/fold/RD Gates. Pair Full applies the qualified Prompt-TSG
relation Gate afterward. Consequently, a compatible relationless pair can enter No-Relation, while a
relation-supported incompatible pair enters neither selector. Changing relation evidence cannot
change the pair's task rows, fold manifest, RD score, or semantic key.

### 24.3 Pair eligibility and optional observational prioritization

For task `i`, the pair context gate requires

\[
q_{C_{q,12}}(T_E(P_i^0))=PRESENT.
\]

Each factor then independently satisfies the Section 5.3 source-state rule for its declared
operation. `ADD x ADD` therefore requires both target features to be absent; mixed and
`REMOVE x REMOVE` pairs require the corresponding absent/present states and every REMOVE neutral
counterpart before variant generation. The pair additionally requires a frozen functional contract,
complete joint-realization support, and a supported Oracle Gate under Section 24.7.

An observational pair selector may be evaluated only when natural discovery data have outcome-blind
four-cell support, adequate task-unit counts, and source-lineage overlap for the two feature states.
If that gate fails, a theory- or registry-selected pair may still enter a separately preregistered
factorial confirmation, but the study cannot claim that observational FCI or another data-driven
selector discovered the pair. Deterministic products such as `X_1 X_2` are not inserted beside
`X_1` and `X_2` in a categorical FCI table merely to manufacture an interaction variable.

The selector recodes each factor relative to its declared operation, so `Z_j=1` always means the
natural target state and `Z_j=0` the operation-specific baseline. Each pair is fit separately. The
primary observational score is a cross-fitted, covariate-standardized risk-difference interaction:
models are trained on deterministic cell-stratified folds and the four predicted response surfaces
are standardized over held-out baseline-eligible task units. The ridge-logit interaction
coefficient is a diagnostic only. Bootstrap sign stability and median absolute score are ranking
diagnostics, not confirmatory confidence intervals. The randomized `2 x 2` experiment remains the
only source of a causal interaction estimate.

Pair Full and Pair No-Relation use byte-identical compatible-pair rows, candidate-specific folds,
support decisions, second-order RD scores, absolute-value rank rule, tie-break, and `K_I`. Only Pair
Full reads the candidate-level relation Gate. Each selector has exactly `K_I` slots; Gate failures,
non-evaluable scores, and an exhausted universe create typed empty slots with no replacement. The
unique union of filled slots is protocolized and confirmed once per model effect coordinate, and its
single randomized result fans out to every selector slot that named it.

### 24.4 Factorial cells and assigned treatment

For factor `j`, `Z_j=1` denotes assignment to its Target operator and `Z_j=0` denotes assignment to
its operation-matched No-op. Every complete block contains:

```text
A00 = N1 + N2
A10 = T1 + N2
A01 = N1 + T2
A11 = T1 + T2
```

These are not the legacy single-feature Specific, Generic, Placebo, and Absent roles. Generic and
presentation-only controls remain in separately frozen single-feature studies and are not silently
added to the primary `2 x 2` family.

Assignment, rather than extracted post-intervention feature state, is the treatment. Factor fidelity,
treatment collapse, and non-target drift are diagnostics and never denominator filters.

### 24.5 Joint realization and cross-cell invariants

One outcome-blind intervention-executor transaction should materialize the four task variants for
one `(pair,task,joint-realization)` bundle when the executor supports structured bundled output. The
transaction receives no model-generation result, Oracle finding, functionality result, expected
effect direction, or prior arm outcome. Each variant and the complete bundle are independently
validated before randomization.

The validator requires the same task semantics, functional contract, pair context, non-target
security requirements, and presentation policy across all four cells. Only `f_1` and `f_2` may vary;
`A11` may not introduce a third requirement. `A10` and `A01` must not collapse to the same target
state, and all four prompt digests must be bound to the bundle.

If the two operators are not prospectively shown to commute, application order is a joint
realization coordinate. Both `(1,2)` and `(2,1)` orders receive frozen positive probability or the
pair is excluded. An observed favorable order cannot replace the other order or renormalize
`Q_{12}`.

### 24.6 Pair block and randomization

The pairwise complete-block key is:

```text
(task_unit_id,
 task_instance_id,
 pair_id,
 pair_context_query_id,
 joint_realization_id,
 factorial_task_bundle_id,
 model_id,
 factorial_protocol_id)
```

Every block contains equally many assignments to `A00`, `A10`, `A01`, and `A11`; the slot count is
a positive multiple of four. The block-specific shuffle is replayable from the frozen randomization
seed and block identity. All descendants of one task unit remain together in bootstrap and
multiplicity calculations.

### 24.7 Oracle support Gate

The pair reuses one frozen Security Oracle profile for the declared policy endpoint. The final pair
protocol freezes:

```text
oracle_profile_id
oracle_policy_sha256
oracle_support_status
interaction_claim_scope
factorial_compatibility
```

`oracle_support_status` is exactly `SUPPORTED` or `UNSUPPORTED` and is decided before randomization.
`factorial_compatibility` must be `COMPATIBLE`; other relation decisions never enter the factorial
freeze even when a pair is supplied manually rather than selected from discovery.
`SUPPORTED` requires the same arm-blind profile and policy digest to apply to the task family and all
four cells, an authenticated mechanism-trace implementation, preserved `unknown`, and a separately
labeled gold calibration that covers the code idioms admitted by the pair. `UNSUPPORTED` pairs do
not enter randomization. There is no pair-specific Oracle and no partial-support status.

`interaction_claim_scope` is exactly `policy_only` or `mechanism_eligible` and is also frozen before
randomization. `policy_only` permits a claim only about the joint Prompt-policy response surface.
`mechanism_eligible` additionally requires that the Oracle endpoint is not mechanically defined as
the conjunction of the two factors and that independent evidence can distinguish both controls.
Statistical significance cannot promote `policy_only` to a mechanism-synergy claim.

The assignment-level Oracle result remains `secure`, `insecure`, or `unknown`. The Gate status is
not an assignment outcome, and factor realization is not substituted for the security label. A
profile that defines full security as the logical conjunction of both controls may identify a joint
Prompt-policy interaction, but that result cannot be promoted to universal mechanism synergy without
an outcome-induced-interaction audit and independent endpoints for the two factors.

### 24.8 Estimands, unknown bounds, and functionality

For model `m`, let `mu_z1z2` be the Section 11 weighted task-unit mean under cell `(z_1,z_2)`,
averaged over the frozen task-bound background distribution `B`. Report:

\[
\tau_1=\mu_{10}-\mu_{00},\qquad
\tau_2=\mu_{01}-\mu_{00},
\]

\[
\tau_{joint}=\mu_{11}-\mu_{00},\qquad
\delta=\mu_{11}-\mu_{10}-\mu_{01}+\mu_{00}.
\]

`delta` is the primary pair interaction and is two-sided. Simple effects
`mu_11-mu_01` and `mu_11-mu_10` are secondary. The observed primary outcome remains
oracle-evaluable secure-code yield. Code validity, Oracle evaluability, functionality, and joint
secure-and-functional success remain separate.

Using the lower and upper cell means from Section 11.4, the interaction bounds are:

\[
L_\delta=L_{11}-U_{10}-U_{01}+L_{00},
\qquad
U_\delta=U_{11}-L_{10}-L_{01}+U_{00}.
\]

Functionality receives its own factorial estimates. A security-interaction claim cannot receive a
practical-success label when the preregistered functionality non-inferiority Gate fails. Static
security with broken task behavior is not silently counted as joint success.

The analysis freeze states whether functionality non-inferiority was separately powered. When it
was not, the Gate is `not_requested` and cannot authorize a practical-success label. When it was,
the Gate uses the simultaneous lower confidence bound for `mu_11 - mu_00` and passes only when that
bound is at least the negative preregistered non-inferiority margin. A point estimate alone is never
sufficient; an unavailable interval makes the Gate `not_evaluable`, not passed.

### 24.9 Simultaneous inference and interpretation

All primary `(pair,model,secure-yield,delta)` coordinates form one frozen max-|T| task-unit bootstrap
family. A replicate samples once from the union of task units represented anywhere in that family;
every pair/model descendant of a sampled unit moves with the same multiplicity. Coordinates may have
partially overlapping support and use only sampled units that belong to their frozen support. Each
replicate is studentized by its own standard error. A replicate is invalid when any tested coordinate
falls below its frozen minimum support or has zero standard error, and the family is non-evaluable
unless the frozen minimum fraction of bootstrap replicates remains valid. The critical value uses the
frozen upper empirical quantile rule. Factor main effects, joint effects, functionality,
per-realization effects, and simple effects are secondary families declared before outcomes. The
independent result verifier recomputes the four cell means, `delta`, resampling family, and Gate
without importing the production estimator.

A positive point estimate is not by itself synergy, and a negative point estimate is not by itself
antagonism. Paper-facing response surfaces use neutral labels such as `positive_nonadditive_pattern`,
`negative_nonadditive_pattern`, `conditional_activation_pattern`, and
`simple_effect_sign_reversal`. A named **security policy interaction** requires a simultaneous
interval excluding zero, the frozen practical margin, adequate support, complete provenance, and
acceptable unknown bounds. A mechanism-interaction label additionally requires
`interaction_claim_scope=mechanism_eligible`. The separate **practical-success** label additionally
requires the preregistered functionality Gate to pass. Otherwise the corresponding claim is
directionally consistent, null, conflicting, or non-evaluable under Section 15.

### 24.10 Minimal implementation and acceptance additions

The extension modifies the existing representation/mechanism, intervention, randomization,
measurement, outcome, inference, workflow, and verifier modules. It must not create another campaign,
measurement framework, Oracle class hierarchy, or deployment system. Measurement and outcome
assembly are reused unchanged unless a scientific invariant requires a versioned field.

Before a pairwise scale-up, focused tests and a representative canary must prove:

1. composite features are rejected as factors and two atomic factors are independently editable;
2. pair eligibility reads no arm, generated code, Oracle result, or outcome;
3. all four cells and every noncommuting order have complete, replayable support;
4. treatment collapse, a third requirement, context drift, task drift, and missing cells fail closed;
5. every assignment enters the total ledger and `unknown` remains distinct;
6. hand-calculated additive, positive, negative, XOR, redundant, prerequisite, and reversal fixtures
   produce the expected main, joint, and interaction estimates;
7. task-unit resampling and max-|T| multiplicity are replayable; and
8. partially overlapping pair supports retain their shared-unit dependence, while inadequate or
   zero-standard-error bootstrap families fail closed; and
9. the independent verifier rejects missing, duplicate, replaced, or digest-mismatched assignments.

### 24.11 Post-confirmation context follow-ups

A completed factorial result may reveal that its source-generation context lacks treatment
positivity, for example because the no-target cell already realizes both controls. A new source
context may then be studied only as a separately frozen prospective follow-up. The completed result
remains immutable and cannot be pooled into, replaced by, or reinterpreted as the follow-up.

When a follow-up retains the predecessor task semantics but changes the generation context, it must:

1. use new prompt, task, corpus, randomization, and study identities while retaining the predecessor
   task-unit IDs for paired context-heterogeneity analysis;
2. retain every predecessor task unit unless an outcome-independent rule was frozen before the
   predecessor outcomes existed;
3. authenticate the predecessor result bundle and declare whether its aggregate or task-specific
   outcomes informed the new design;
4. freeze the new context, factor texts, model, Oracle, estimands, multiplicity family, practical
   margins, and claim boundary before any follow-up provider outcome;
5. qualify any supplied code scaffold for syntax, Oracle evaluability, and intended pre-treatment
   mechanism state without using generated outcomes;
6. use development-only task units for a behavior canary so formal follow-up tasks remain unexposed;
   and
7. describe cross-context differences as context-conditioned policy heterogeneity, not as a
   retroactive confirmation of the predecessor or a universal mechanism effect.

Mechanism-trace rates may be predeclared as assignment-level diagnostics and independently
recomputed. They remain post-assignment implementation markers, not causal mediators, primary
outcomes, eligibility rules, or denominator filters.

This extension can produce a meaningful null, harmful, beneficial, or interacting policy result. A
failure to obtain statistical significance is not permission to change the same frozen pair,
population, endpoint, Oracle, arm text, denominator, or multiplicity family after unblinding.

## 25. Controlled Discovery-Population and Analysis Migration

This section is the prospective D0--D5 migration contract. It changes no completed artifact and
adds no scientific stage, selector family, outcome, or estimand. Until every referenced rule is
frozen, the framework remains `SPECIFIED_DRAFT` and formal execution is prohibited.

### 25.1 D0: coverage-aware Discovery-population preparation

Representation qualification precedes any formal coverage census. The census is computed only from
qualified, natural, deduplicated task units that are eligible for the `DISCOVERY` role and have not
been exposed to outcomes or selector outputs. A frozen `CoverageTargetProfile` identifies the
contexts and atomic feature states to count, minimum state-cell task units, minimum independent
source lineages, permitted source families, maximum acquisitions, stopping rule, and exactly one
supplementation round.

The four logical D0 artifacts are:

1. a pre-supplement census over the frozen coverage target;
2. an outcome- and selector-blind supplementation plan;
3. an acquisition receipt authenticating source, license/provenance, natural-task identity,
   deduplication, and role eligibility; and
4. a post-supplement census computed by the same representation and Gate implementation.

Capacity recovery on existing unexposed task units is attempted and reported before external
acquisition. Context-first acquisition is the default. State-targeted acquisition is allowed only
when its state-only sampling rule was frozen in the profile and is disclosed. Paraphrases,
intervention-generated Prompts, synthetic records, duplicated task descendants, and constructed
four-cell completion are forbidden. The plan and receipt cannot contain natural outcomes, FCI/PAG
evidence, RD values, selector ranks, Full/ablation membership, or Prompt-TSG relation support.
Discovery and Confirmation capacities remain separate; supplementation cannot borrow, relabel, or
consume Confirmation task units.

The repository implements and validates these records now, but does not execute acquisition while
the qualified population and author-owned thresholds are unsettled. Missing targets or a second
round fail closed.

### 25.2 D1: population-version binding

`DiscoveryDesignFreeze` binds the accepted pre/post census lineage, qualification identity,
`CoverageTargetProfile`, supplementation decision (`NOT_REQUESTED`, `PLANNED`, or `COMPLETED`),
permitted data roles, and the exact Discovery population manifest. Candidate universes, folds, FCI,
RD, and selector ranks must all point to that same population identity. A changed member, role,
representation digest, target profile, or census invalidates downstream discovery artifacts rather
than silently regenerating them under the same freeze.

### 25.3 D2: unified candidate discoverability and no-heredity Pair admission

Every Atomic and Pair candidate stores one typed discoverability decision with a finite reason
vocabulary and references to the candidate universe, natural-support audit, fold freeze, and
population identity. Its only statuses are `DISCOVERY_ELIGIBLE` and `DISCOVERY_INELIGIBLE`; the
record retains state/four-cell counts, unique lineages, near-duplicate-safe counts, representation-
resolved rate, Oracle-ready count, confirmation-baseline count, fold evidence, and finite reason
codes. Atomic discoverability requires its context/source-state support and Atomic fold
prerequisites. Pair discoverability independently requires its pair context, factorial
compatibility, natural four-cell support, source-lineage overlap, and Pair fold prerequisites.

Atomic selection, Atomic FCI adjacency, Atomic RD rank, and Atomic support decisions are forbidden
Pair inputs. Therefore a Pair may be discoverable and selected even when one or both factors are not
Atomic candidates. Tests must include such a pure-interaction fixture and prove that changing Atomic
artifacts cannot change Pair rows, folds, score, rank, or eligibility.

### 25.4 D3: prospectively frozen context modifiers and contrasts

Context modifiers are Stage-III analysis coordinates, not new selectors and not policy-key fields.
A modifier specification freezes a stable identifier, source field, finite levels, missing-value
policy, task-unit assignment digest, eligible policy family, estimands, contrast family, minimum
support, bootstrap coupling, and multiplicity family before confirmation outcomes are loaded.
Primary assigned-arm task-unit ITT remains unchanged; modifier analyses are predeclared secondary
heterogeneity analyses and retain every assigned unit under the frozen missing-value policy.

The current draft authorizes schema, provenance, validation, and report/verifier plumbing only. The
exact modifier levels, joint bootstrap rule, multiplicity family, and support thresholds are not yet
frozen. Activation therefore returns `BLOCKED_NO_FROZEN_CONTEXT_RULE` and cannot produce intervals,
statuses, tables, or claims.

### 25.5 D4: deterministic Pair response-pattern classification

Pair response patterns are deterministic post-estimation summaries of the verified four assigned-arm
means, main/joint/simple effects, interaction estimate and simultaneous interval, frozen practical
margins, unknown bounds, functionality Gate, and claim scope. They never affect candidate identity,
support, ranking, selection, replacement, randomization, or estimation. Atomic effects record the
classifier as `NOT_APPLICABLE`.

The neutral label vocabulary and the exact mutually exclusive predicates and precedence order have
not been author-frozen. Pair results therefore store the four-cell response surface and
`BLOCKED_NO_FROZEN_PREDICATE`, with no label. A missing predicate must not be represented as
`NONE`, `null-without-status`, or a default scientific interpretation. Once frozen, production and
the independent verifier must implement the predicates separately and compare the result.

### 25.6 D5: evidence and report integration

The schema-3 result bundle retains its single exact file set. The new population lineage,
discoverability decisions, inactive context-analysis plan/status, Pair response surface, and
classifier status are nested in their owning frozen records and evidence rows. Result authorization
must reject any active context or response-pattern claim whose rule digest is missing, any Pair path
that reads Atomic selection evidence, and any population identity mismatch. Smoke and fixture
outputs remain `tested`, never `executed` or `reported` evidence.

Implementation readiness means that these schemas, validators, fail-closed states, result fields,
independent reconstruction, and representative tests pass. It does not mean that D0 acquisition,
formal Discovery, Confirmation, or any scientific claim has run.
