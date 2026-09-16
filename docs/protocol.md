# Prompt Mechanism Study Context-Conditioned Intervention-Policy Framework

**Date:** 2026-08-20

**Status:** `SPECIFIED_DRAFT`

**Prospective protocol ID:** `phase-context-policy-v3`

**Prospective schema family:** `3.x` (not yet authorized for formal execution)

**Draft revision:** 2026-09-13 CausalGuide paper positioning and specified evidence-to-explanation reporting contract; retains the 2026-09-12 source atoms, program-assigned IDs, role declarations, exact factor scopes, separate applicability/expression judgments, and source-semantic qualification

**Scope:** Prospective theory, discovery, hypothesis selection, randomized confirmation,
inference, evidence-grounded explanations and guidance, and paper-facing research questions

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

Previous specifications are recoverable from Git history; every frozen artifact produced under them remains immutable. They
must not be edited in place or represented as having been generated under this framework. This
framework remains `SPECIFIED_DRAFT` until every author decision, qualification artifact, budget
Gate, implementation, independent verifier, and reviewer reproduction required below closes. Only
then may its status become `FROZEN`. A run must declare either a legacy protocol or the frozen form
of this protocol; it may not silently mix their hypotheses, estimands, schemas, data roles, or
evidence labels.

## 2. Scientific Positioning

CausalGuide is the paper-facing method name for this research prototype. Its title is
**Causal Analysis for Explainable Security Guidance in LLM Code Generation**.
The repository name, protocol ID, schema coordinates, implementation identifiers, and frozen
artifacts are unchanged. CausalGuide is not a new general-purpose causal-discovery algorithm and
does not claim that FCI recovers the unique causal mechanism of Prompt authoring. It studies how
changing a task-bound security requirement's expression affects generated-code outcomes, and
what those effects support as explanations and prompt-modification guidance:

```text
task-grounded structured graph representation
  -> context-conditioned requirement hypotheses
  -> observational prioritization under latent-variable uncertainty
  -> frozen multi-realization Prompt policies
  -> held-out randomized security evaluation
  -> evidence-grounded explanations and scoped guidance
```

The central scientific problem is to connect task-local requirement meaning, causal evidence for
a concrete Prompt change, and the action that evidence can support. Structured representation
identifies the relevant operation, object, conditions, and non-target behavior. Randomized policy
effects supply evidence about changing requirement expression, not the generator's internal
reasoning or a universal causal property of a concept. The reporting contract in Section 15.1
keeps source facts, observational selection evidence, randomized effects, and guidance distinct.

Budgeted hypothesis selection supports this objective and retains its original evaluation rules.
Given a fixed discovery dataset and a finite intervention vocabulary, a selector receives exactly
`K` slots and prioritizes policies for held-out randomized confirmation.
In the Atomic Full selector, FCI supplies a latent-confounding-
aware local structural-admissibility Gate and the shared cross-fitted first-order risk-difference
score supplies the rank. Atomic RD-only uses the same universe, rows, folds, score, tie-break, slots,
bridge, and confirmation but does not read the FCI Gate. Pair Full and Pair No-Relation analogously
share an independently compatible universe and one second-order risk-difference score; only Pair
Full reads the qualified Prompt-TSG relation Gate. Neither FCI nor a Prompt-TSG relation identifies
the final effect. Random assignment identifies the frozen Prompt-policy effect.

The paper organizes its methodological contributions as:

1. **Task-grounded requirement-level causal analysis:** structured task semantics define single-
   and two-requirement comparisons, observational prioritization allocates evidence-acquisition
   effort, and independent randomized confirmation estimates frozen policy effects.
2. **Evidence-grounded explanations and security guidance:** task scope, concrete edits,
   effect evidence, functionality, uncertainty, and action boundaries form one inspectable
   explanation product. Its perceived utility is evaluated separately in RQ4.

The paper uses three reader-facing stages: **Structured Graph Representation** (representation),
**Requirement-Level Causal Analysis** (prioritization, hypothesis freeze, intervention/randomization,
measurement, outcome assembly, and inference), and **Evidence-Grounded Explanations and Guidance**
(the human-facing reporting part of inference/reporting). These headings reorganize presentation;
they do not add a scientific stage or execution path. The reviewer artifact retains the seven
explicit operations and their immutable boundaries. Optional D0 remains pre-Discovery preparation.
This positioning change does not activate the protocol or change an RQ estimand, arm family,
denominator, budget, multiplicity family, or experimental role.

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

The sole pre-Discovery role-manifest extension is the bounded D0 addition in §25.2.
It preserves every existing binding and adds only new independent `DISCOVERY` bindings.
Qualification results retain their original manifest identity; the accepted extension
does not reissue an acceptance result or reopen `QUAL_ACCEPT`.

### 4.1 Discovery regime

For task unit `c`, task instance `i`, model `m`, and request-randomness slot `s`, let
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

For a prospectively defined **explicit prompt-requirement** feature, `ABSENT`
means that complete source review finds no expression of that requirement; it
does not mean the generated program lacks the protection. A source need not
explicitly request insecure behavior to support ADD. Implicit requirements,
ambiguous wording, or incomplete inspection remain `UNRESOLVED`. Existing
feature definitions and frozen unknown states cannot be relabeled under these
semantics: the new query meaning must be recorded and qualified before formal
Discovery. An addition must preserve the source operation and non-target
requirements. REMOVE still needs the identifiable original requirement; its
neutral counterpart is constructed during protocolization, not demanded from
the natural source. The final operation gate retains that counterpart check.

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

The generic type system separates inputs/objects, operations, functional requirements,
safety requirements, conditions and presentation requirements. Typed edges express input use,
outputs, operation order, requirement-to-object scope and conditions. They are semantic relations,
not causal edges. A concept is distinct from its task-local instances: two SQL operations retain
two nodes, even when their concept and operation type agree. Each node binds its own source span.

#### One source-only instance contract

The active annotation path is `prompt_contract_extract.extract_contract_task_file` with a schema-2
concept catalog and the schema-3 `OpenTaskContract`. It first inventories source facts, lexical
coverage and layers, then allocates fact IDs in the program and uses a separate call to declare local roles and bind those fixed IDs
into a graph submission. For a frozen vocabulary, a third source-only call assesses fixed scopes
from that submission. The first model draft is not a qualified or scientifically frozen TSG.
The binding call is skipped when there are no binding rows; the scope call is skipped when
there are no eligible source-bound scopes. Incomplete inventories retain their withholding
reasons and any enumerable scopes, never a silent successful empty result. This remains one
representation stage, with no automatic retry/repair loop, and does not guarantee a complete graph.
The active prompt is `data/method/open-tsg-annotator-v15.md`. Binding request rows list only
column names to fill; allowed target IDs live in the response schema, are restricted by type and resolved
layer, and assert no relation. Source-cited operation/object roles are declared once;
the compiler derives the corresponding input/output edges instead of requesting them again.
Earlier prompts and saved results
retain their captured response formats and original call structure.
Before annotation, `task_input.prepare_task_input` prepares the baseline input once: preserve the
unaltered source and its hash, replace the literal `<language>` template token using the declared
language, and record the exact generation system message and user request. For the current Python
development scope the common system message is explicit; other scopes need their own declared
message and do not inherit Python instructions. No label or generated outcome supplies missing
language information.

The annotation `source_prompt` is a deterministic evidence view of **both actual messages**:
`System message`, followed by `User message / Language / Task`. These headings identify provenance;
they are not additional instructions sent to the code generator. System-level constraints remain
distinguishable from task text. The request also contains generic types/relations and the applicable
concept policy. All node/edge spans and the graph hash bind this complete baseline view. The
extraction bundle includes the prepared `tasks.json` needed by intervention and generation.

`task_input.generation_template_facts` handles only an exact match to the declared default system
message with language `python`. It emits five source-bound generation-layer facts: implement the
task, preserve required interfaces, preserve non-target behavior, return the declared JSON code
object and use Python. The latter four constrain the implementation operation through four fixed
edges. These are declared input-template semantics, not inferred runtime behavior. Annotation
cannot replace those facts or reconsider their edges. A custom message, even one with similar
wording, does not receive this shortcut; its system text and language remain source annotation
inputs. Frozen catalogs must contain the exact template concept types and meanings.

The current operation-bound ADD renderer edits only the user-task portion. All five arms share the
same system message and language. Generation reconstructs those exact messages from the represented
arm; a changed common context, unfilled language token, stale graph, or mismatched functional
baseline blocks execution before a provider call. The functional judge receives the complete,
untreated baseline input, never an arm's added requirement. Seeds repeat code generation; they do
not multiply independent task units or require another baseline TSG extraction.

External CWE labels, task-family labels, task identity, selector outputs, generated code and
outcomes never enter this request. Original source text can still contain topical labels.
The earlier development runs used raw-source-only graphs plus additional generation context.
They retain their original inputs and results; reading or verifying them does not establish this
new input-alignment boundary and does not authorize reusing their graphs for prepared inputs.

During `DEVELOPMENT_OPEN`, concrete task concepts are induced from already exposed development
prompts. The request withholds task-concept seeds and operation-feature checks: they cannot
narrow extraction to the candidate security requirement. It supplies generic node/relation roles
and the exact declared template facts, when applicable, and asks for the full task, including
non-target behavior and any remaining generation constraints.
Feature-state review occurs separately against the full source; omitted states remain unknown.
During `FROZEN` graph extraction the reviewed vocabulary is supplied, while feature-state checks
are withheld until graph construction is complete. The graph response does not repeat vocabulary
definitions or assess states. During open development each node carries its complete inline concept; no new concept
or node needs a cross-reference within that first response. Relations reference the program-assigned IDs.
The active representation annotation proceeds linearly: source fact inventory, fixed-ID bindings,
then fixed-scope states. `contract_decision_request` first asks for source-bound nodes,
their `generation`/`runtime`/`unresolved` layer, source-unit keys, coverage and unresolved
notes. `_source_units` partitions text lexically and supplies fixed keys. Nodes have
no local IDs. Each coverage row contains status and reason, without a fact-ID list;
`_indexed_facts_response` allocates `fact.1`, `fact.2`, ... and constructs the inverse
source-unit/fact mapping. `no_task_fact` means no additional fact beyond the supplied
fixed template. Model coverage declarations still require source review. During open
development inline concept IDs must have consistent types and complete definitions;
frozen extraction can only select known concepts. Unsupported or missing meanings
remain unresolved, never replaced with a nearby concept.

When exact concept/source-span duplicates are merged, the initial inventory's
coverage and layer references follow the compiler's same instance aliases. A
successful merge is not missing evidence. Conflicting layer declarations are
rejected; actual citation failures remain unresolved. Distinct atomic concepts
sharing a sentence are not merged by their shared citation alone.

Requirement composition belongs to construction. Each record declares `structure.kind` as
`atom`, `and`, `or`, compound `not`, or `opaque`, with members referencing existing requirements.
An atom preserves the complete predicate, negation, quantifiers, thresholds, targets and guards.
The finite expression forest retains composite meaning; it is not a general logic solver.
Conjunction entails its declared members and the compiler inherits parent guards on descendants.
Alternative and compound-negation members are not independently asserted requirements; opaque
expressions remain unresolved. Only asserted atomic obligations can supply positive feature
evidence or Atomic candidates. A simple prohibition is a complete negative atom. Separate
semantic atoms do not establish independent editability. Targets remain explicit per member;
program validation cannot establish that the declared composition matches the source.

The active `source_records.attempt_graph` path supplies `unit_impacts` for every source unit,
with exact quotations and local/global/unresolved/no-runtime-effect scope. The same source
review checks these declarations. Recorded dependencies establish a lower bound on affected
operations, never a certificate of unrelatedness. An incomplete local unit blocks its affected
operations; shared/global or unlocalized uncertainty blocks every potentially affected scope.
Generation-layer requirements are not automatically irrelevant to runtime comparisons.
Operations distinguish execution guards (`conditions`) from source-supported non-gating
`scope_conditions` (`context_for`). A requirement guard alone cannot manufacture independent
context. Context must survive the target intervention; missing evidence leaves binding unresolved.

The program retains deterministic `structural_readback` of record bindings as debug
output before and after the existing review. Compilation and readback share
condition inheritance and target expansion. Requirement guards come only from condition
fields; direct targets come only from scope/target fields. Empty conditions declare no
structural guard. A condition mentioned in prose does not repair an empty list. Execution
guards, non-gating context and requirement conditions remain distinct. Adding readback
and bidirectional source checks to the paid review showed no incremental detection gain
in the bounded development comparison; that prompt addition is not active.
An experimental review required separate complete-binding judgments and source-unit
coverage explanations. Its two-task comparison showed a local detection gain but
still missed a deleted source condition and did not meet its adoption gate. It is
not the default paid component; the sole active path uses the ordinary record/source
review. Frozen experiment sources retain the detailed variant for reproduction only.
A model-approved record remains a fallible diagnostic, not source qualification.
Equivalent complete structures are admissible. Whole-field addresses, including empty
arrays, are available in `rejected_claims`; a local patch must change the rejected claim,
not its explanation alone. Participation and source completeness remain part of the same
review. Deterministic decoding exposes field meanings but cannot certify source
equivalence. Controlled variants are development diagnostics, not new natural tasks.
Local patch merging preserves accepted `unit_impacts`. Only source units marked
`complete=false` by the existing review may update their influence declarations;
correcting a direct target does not authorize narrowing source influence.

Each object role cites its source clause and binds an exact operation/object pair. Roles are
`value_input`, `identifier_input`, `resource`, `destination`, `input_unspecified` or `result`.
An object may be an input and a result when the source supports both, including within one
operation. Roles are local propositions, not a permanent global input/output partition or a
prediction of generated code. `value_input` includes userid and filepath values stored or
matched in SQL; `identifier_input` means a structural name or locator, such as a table/column
name or a path used to locate a download. An entity's identifier is not automatically an SQL
identifier. The request supplies these definitions and distinguishes resources, destinations,
unresolved input roles and produced results.
`apply_fixed_binding_response` derives one `produces` edge for a result role and one `used_by`
edge for an input role, preserving their source citation. Several supported input roles may
share a single incidence edge. Roles are retained beside those derived edges; no second model
assertion is required. The first response contains no operation-role table. Neither
step assigns a feature state. The binding call cannot repair,
relabel or add facts. The combined inventory and binding response form the graph submission for
scope assessment and source review, without granting scientific qualification.

`fixed_binding_request` provides a required row for each non-template operation, requirement/constraint/
presentation control and condition predicate. The template relations are retained unchanged.
Operations have only a precedes column;
requirements separately have operations and subjects columns; conditions have operations and
requirements columns. The request lists only these column names; the response schema separately
enumerates existing IDs of the allowed target type and same resolved layer as choices, never
asserted relations. Input/output relations come exclusively from source-cited local roles;
operation order is restricted to runtime operations. An unresolved layer supplies no candidate
bindings. These restrictions prevent the submitted graph from freely mixing generation instructions
with runtime data, but a model's wrong layer or local role remains a semantic error for source review.
`apply_fixed_binding_response` converts these columns to the existing TSG relation types. It
rejects omitted rows/columns, unknown or wrong-role endpoints, duplicate selections and invalid
relation citations. Each selected relation cites its supporting source clause. Empty arrays assert
no relation; they do not establish absence. A subject-specific requirement still needs both its
operation and its objects, and a requirement condition does not automatically qualify the operation.
A missing fact, a semantically wrong label or an omitted subject is not repaired by this format;
it remains a source-review limitation. These are changes inside representation, not new scientific
stages or an alternate extractor.

The generic role `condition` denotes a source-stated predicate qualifying an action or requirement.
It is distinct from an unconditional `constraint`, such as the implementation language. Only
`condition` may originate `conditions` edges. Ordinary implementation/answer requirements bind
their stated implementation target; they do not activate runtime branches. Resources and
destinations explicitly participating in an operation count as its `inputs`, not only scalar
arguments. Their separate local roles remain visible to applicability assessment; being an input
does not make a resource or destination a parameterizable scalar value. These definitions are
prospective; old condition-as-constraint artifacts require
their captured implementation and retain their original verdicts.
An invalid or unbound condition edge closes the extraction attempt as a failure. It cannot be
silently dropped and thereby manufacture unconditional scopes. Other partial-evidence handling
remains unchanged. Type validation cannot prove that a condition predicate was semantically
justified or that none was omitted; independent source review remains necessary.

The HTTP encoder preserves the declared response-schema property order, including inline
concept information and start-before-end coordinates. Source-message serialization and artifact
identity remain canonical JSON. This keeps the delivered schema consistent with the declared
annotation sequence; it does not establish that a provider follows that order or that ordering
improves semantic accuracy. Frozen earlier calls and their replays retain their captured encoder.

`contract_decision_request` internally indexes words/punctuation in the complete unchanged
source prompt, using `\w+|[^\w\s]`. Tokens have no semantic or candidate labels. The active
grouped inventory hides those positions and asks for a source-unit key and a literal quote
occurring exactly once inside that unit. The program requires word/punctuation boundaries
and computes the inclusive token positions; an ambiguous or modified quote fails instead
of guessing a match. Fixed binding assertions still select indexed evidence and the compiler
retrieves the exact source substring. Token boundaries preserve separate arguments in `f(x,y)`;
spans may include original intervening whitespace and multiple sentences. Invalid pointers
leave fact assertions unbound and diagnosed; invalid binding pointers fail that annotation while
preserving the earlier fact inventory. Valid pointers can still support an incorrect
concept or relationship, which requires source-semantic review. This change does not normalize
old raw answers or convert a former annotation error into a qualified result. The active extractor
uses one format per stage; frozen earlier responses require their captured implementation.
Signature preservation, return-convention preservation and
all-behavior preservation are different concepts. Mere input use is distinct from validation;
HTTPS transport is distinct from a certificate-validation requirement.

`fixed_scope_request` then enumerates each matched operation, its individually declared local inputs,
the explicit full input set, and condition sets bound to the operation or its requirements.
The operation-level empty-subject scope is separate. Arbitrary other subsets remain unassessed.
An optional, prospectively declared `feature_scope_domains` map in a schema-2 catalog
makes the arity of every queried feature explicit: `operation` applies to an operation
without subject IDs; `subjects` requires named subject IDs. The declaration is part of
the catalog identity and must agree with the full concept definition; it is not learned
from treatment outcomes or from a desired scope state. `fixed_scope_request` exposes
the domain per scope. A coordinate with unbound arity remains present and unresolved;
it is neither absent nor not_applicable. `fixed_scope_response_format` restricts its
applicability answer to unresolved, and `validate_prompt_tsg` independently rejects
a decisive state for that coordinate if a model ignores the schema. This arity check
does not establish semantic applicability for a named subject, erase a condition,
or supply a missing expression judgment. Catalogs predating this declaration retain
their captured interpretation. The current domain-bearing profile is under bounded
development validation; it is not a qualified representation profile.
Source-reference evaluation must use the same declared feature domain. The
prospective development reference `source-reference-arity-alignment` corrects
two old empty-subject negatives while retaining every named-subject judgment.
Its optional `evidence_alignment=semantic_overlap` matches the same concept and
type through a shared alphanumeric source span, rejecting ambiguous matches and
reuse of one model instance for distinct reference instances. This aligns source
mentions only; it cannot establish completeness, full predicate meaning or absence
of unsupported assertions. Those still require source review. References without
this option retain containment matching, and old results are never regraded.
Subsequent development uses `source-reference-coreference-alignment`, which
retains those requirements and prospectively adds reviewed alternative mentions
of the same source entities. An input cited in its use-site description need not
be quoted from its signature occurrence. This uses the existing alternative-anchor
mechanism, keeps every required node/relation/scope and the distinct-instance guard,
and does not make a correct citation proof of correct semantics. Older frozen
scores remain unchanged; retrospective matcher fixtures are not new model results.
`_inventory_status` checks unresolved source coverage and layers, missing declared-role
bindings and whether any runtime facts were submitted. The binding response also
provides `unit_impacts` for EVERY source unit: completeness, local/global/unresolved/
no-runtime effect, affected runtime operation IDs and a source-specific reason.
This review must consider the whole source, shared inputs, downstream dependencies,
conditions and non-target obligations. Missing edges never prove independence.
After validating the submitted bindings, `apply_fixed_binding_response` includes
the dependencies already represented by source-unit ownership, operation-local
roles and condition/requirement bindings in each local impact list. A source
object concerns its declared consumers and producers; a produced result can
carry that dependency to later consumers. Condition and requirement bindings
carry it to their named targets. Mere `precedes` edges do not propagate data
dependence. This is a conservative description dependency, not a causal effect
or proof of complete source coverage. Model-declared broader reach is retained;
incomplete, global and unresolved declarations are never upgraded to complete.
A no-runtime-effect claim that conflicts with represented runtime dependencies
becomes explicitly unresolved. Raw model impact lists remain in the retained
binding response. Frozen older runs replay through their captured implementation.

The binding request supplies explicit meanings for precedence, constraints and
conditions. Precedence requires source-mandated order or availability of a result
to its consumer; sentence order, shared inputs and customary implementation
choices do not establish it. This rule still needs source-semantic review; a
valid quotation alone cannot prove the relation.

The current bounded development delivery uses source-first JSON presentation:
the original source precedes candidate material and source-token keys retain
numeric order. `operation_incidence_request` now allocates one participant frame
per runtime operation. Its `operation_subjects` list is the admissible object
vocabulary, not a claim that every listed object participates. Each response
frame contains source-cited `inputs`, `results` and `unresolved_subjects`. Omitted
objects assert no relation; missing whole operation frames are errors. Inputs
and result exposure remain independent. Duplicate roles, invalid immutable
endpoints and use of a result as an input-role label are rejected.
`flatten_operation_incidence_response` compiles these lists into the existing
role and edge contract. Genuinely unresolved participants preserve affected
source-unit incompleteness and scope withholding. No absent software property
is inferred from an omitted prompt relation. These changes add no scientific
stage or graph fact and do not certify source meaning. Earlier dense pair-table
runs retain their captured implementation; that table is not another active
delivery path. The current frame candidate is implemented and offline tested,
with no new real-model quality result.

The existing source-annotation review also accepts the incidence response. It
expands each claimed role with its operation, object definition and source quote,
retaining an exact path into the original operation frame and input/result list
regardless of JSON key order. Its completeness review follows the declared impact policy. A source-only
critic can propose corrections; it does not qualify the graph. The bounded
development adapter supports fresh inventory, at most one replacement on
mechanical inventory validation failure, initial bindings, one source-first
critique, at most one same-schema binding revision, then scope assessment. The
bound is four mandatory calls, one separate source-only relation reconstruction
when there are runtime operations, and at most one inventory and one shared
binding replacement (at most seven calls). No inventory critic is used. The
independent review sees source, fixed runtime operations and objects, but no
proposed bindings or earlier verdicts. It answers every operation/object pair with
a nonempty role list or a singleton no_required_role/unresolved marker; there is
no second existence verdict. This independent table is delivered as json_object
with its schema in the system prompt and local pair/role validation; other stages
retain native schemas. This delivery choice is under bounded development testing,
not qualification. It reconstructs required order. Pair disagreements and missing order proposals join
the same fallible binding repair; no edge is added or removed automatically,
and existing transitive paths count as represented order. A no-required-role
proposal is not a security absence judgment. Type evidence quoted inside a
condition-bound source fact is withheld outside that fact's conditions; this
checks citation scope, not universal semantic validity. These checks remain
bounded development, not stability qualification.
The replacement uses the existing source-only diagnostics; a second invalid
answer remains failed. The critique checks required participant uses per
operation, including independently produced results and shared resources, before
reviewing proposed claims. Resource use follows the original specification's
abstraction level: an unstated implementation handle or an earlier operation's
use cannot exclude another stated use of the same facility. A nearby mention or
import alone does not establish use. Empty critiques skip revision, and a critique
requiring new inventory facts terminates that case rather than changing immutable
facts in the binding stage. Full source/contract review remains required. The
cached-draft pilot and fresh control-flow fixtures are distinguished from real
fresh workflow evidence in `tsg-workflow-stability.md`.
The current bounded candidate uses `source_binding_entailment_request` to ask for
each operation's whole results, direct inputs and unresolved subjects from the
complete source and fixed fact meanings. It withholds the draft's role and
completeness answers. The model also lists residual missing meanings for every
source unit; an empty list means no remaining gap, including redundant examples
and presentation labels. Proposed non-role relations retain separate support
verdicts and actionable issues. Role answers copy an exact contiguous original-source
passage and its occurrence; the program verifies that pair and converts it to token
coordinates. Creation of a new value does not imply consumption of that result;
using and exposing an already available value requires separate source support.
An object mentioned elsewhere does not establish an input relation to this
operation. `input_unspecified` requires established use with an unresolved role;
it is not the default for unmentioned pairs or merely possible future code use.
`source_binding_review_revision` compares both roles and citation coordinates
with the draft to produce feedback for the existing single repair. Each issue
quotes the relevant passage; the complete source remains in the request. It never
edits the graph directly. Missing inventory facts terminate binding-only repair.
These constraints prevent invalid endpoints and routing, not false semantic
judgments; source-derived answers remain fallible proposals.
The independent binding review receives each fixed fact's generation/runtime
layer and existing fixed template relations. These are prior source context,
not the hidden draft role or completeness answers. Source-specific interface
constraints concern the generated implementation; a layer by itself does not
prove a proposed edge, and imports alone do not require runtime facility use.
Inventory review and replacement must preserve source-supported core meanings
when correcting an over-specific concept. Use an admissible broader concept or
retain an explicit unresolved meaning if none exists; do not erase a stated
entity by deleting its unsupported specialization. Equivalent concepts for one
source instance should not create duplicate aliases. Recheck source coverage
after deletion or retyping. Binding repair feedback uses concise shared guidance and
retains every issue path, source quotation, stage and role/citation proposal.

For a prospectively declared named concept, `source_name_terms` specifies
alternative literal names that must occur in its own identity evidence.
`has_required_source_name` matches case-insensitively with ASCII identifier
boundaries; a name inside a longer identifier does not match. The current
bounded catalog requires `MySQL` for `resource.mysql`, so `MySQLdb` alone cannot
supply that fact. `contract_decision_request` excludes named concepts whose
literal prerequisite is absent from the actual source; the graph builder and
validator also check each selected node's own source span. Explicit `mysql
database` / `MySQL database` positives remain eligible, and the generic database
concept remains available. Nothing is automatically retyped or declared absent.
This is a necessary evidence condition, not an entailment oracle: a literal
name in an import, negation or unrelated mention still does not establish a
runtime entity. Full source identity, role and completeness review remains
required. Names or aliases outside the declared terms must be retained as a
source gap when they cannot be faithfully represented; old catalogs/results
retain their captured policy and meaning.
The provider's native operation-frame schema omits its unsupported `uniqueItems`
keyword; the local response parser still rejects duplicate participant records.
The common provider client retains bounded, credential-redacted HTTP error bodies
for diagnosis. Neither change establishes semantic correctness.

`value_input` means direct use of a data operand, including field extraction,
forwarding or returning an unchanged value. A received request or parsed document
is data at its extraction operation; being the source of extraction does not make
it an access facility. `resource` denotes facilities such as a database, base
directory or source file. A facility can be named by a path without becoming a
separate caller-supplied locator. `result` denotes production or exposure of the
whole named object, including an existing return value. Roles may coexist, but
contributing part of a collective does not produce that collective. Ambiguous SQL
value-versus-selector roles remain unspecified.

The bounded development path begins with required actions, then their source-supported
operands/results and atomic requirements, in one grouped source inventory. Necessary
unnamed results are represented; optional implementation details are not. Each operation
submits its input/result objects together with separate source citations for their roles.
Each object occurrence declares an `entity_key`: repeated mentions of the same entity
reuse that key and concept, even across different noun phrases and literal quotations.
The program pools this explicit coreference, retains its first identifying quote and
unions source-unit references without adding runtime edges. Conflicting concepts/layers
for one key fail compilation. Coreference is still a fallible semantic assertion requiring
source review; similar wording alone cannot establish it. The program assigns final fact
IDs independently of those temporary keys. A source critic inspects this actual draft's
expanded atoms, provisional roles, coreference keys and source coverage. Unlocated
quotations remain visible with their submitted source-unit/text pair and a location
error, so repair can address them before final compilation. A null citation is not
source approval. The critic reports source-cited concrete issues and omissions. If
there are issues, one inventory replacement verifies them against the source and
preserves correctly represented meanings. Otherwise the original draft is retained.
The final compiler still rejects invalid citations. Independent re-extraction and
reconciliation are no longer the active inventory-review mechanism. A broad evidence citation is not by itself a compound
assertion: atomicity concerns the selected concept's full meaning. Instance identity
is a separate requirement: distinct occurrences of the same operation concept
need non-overlapping identity anchors, while wider supporting context stays in
source units. Exact duplicate instances may merge; different concepts may still
share evidence. Mechanical diagnostics expose overlap to review/repair, and
unresolved overlap prevents compilation. Binding rechecks and replaces these
provisional role claims before committing edges. Source facts remain immutable during
binding; missing facts still block completeness. The current candidate removes a redundant
task-specific function-interface label in favor of the generic function-signature concept
and its exact source instance; frozen older vocabularies and references remain unchanged. The generic
interface template does not replace the named task interface. The prospectively bounded development candidate documented in
[TSG workflow stability](tsg-workflow-stability.md) currently tests fresh Max inventory and fixed incidence, source-only binding
review with at most one repair, then fixed-scope assessment. Inventory critique
is inactive. The existing review/repair behavior below is used for bindings, with
explicit source-necessary role and ordering checks. Complete final source review
remains required. Formal activation and scientific completion criteria are unchanged.
The actual system instruction and request must agree: object anchors identify one
entity, with complete context in supporting source units; complete atomic
requirements retain negation, thresholds, cardinality and conditions. Module
imports and imported symbols use their distinct declared meanings. The critic
retains complete role/relation definitions. Necessary result dependencies do not
require explicit temporal words and do not assert an implementation schedule.
The final binding compiler expands each submitted role citation to contiguous
source context covering its original token span and the source units citing its
operation/object endpoints. The raw response retains the model-selected span;
fact identity anchors and role/edge meanings do not change. This mechanical
context completion preserves antecedents and is not semantic validation. Frozen
older contracts keep their original citations. Scope assessment separately checks
every required type, measurement unit and context in a feature definition when
no frozen applicability derivation is supplied. A value-input role does not prove
a character-valued domain; missing domain evidence remains unresolved even when
the requirement is clearly not expressed. The compiler adds no type assumption
or automatic state correction from names, labels or the reference answers.
Native inventory outputs select known concepts and literal source-unit evidence.
The critic audits the actual draft against the complete source and may request
one replacement for concrete defects, preserving supported core meanings and
checking omissions.
After source facts are allocated, a `no_task_fact` coverage label on a unit owning
submitted facts is normalized to `represented`, with the original reason and
correction retained. This derives occupancy only: it adds no fact, never promotes
`unresolved`, and does not repair `represented` with no facts. Independent source
completeness review remains mandatory. Earlier frozen artifacts retain their
original behavior. The compiler still rejects remaining mechanical inconsistency.
Review distinguishes operation execution guards from conditions qualifying an
obligation. Reviews are fallible feedback,
not automatic semantic acceptance. The binding critic reviews the actual draft,
including every expanded role, binding and source-completeness claim. Fixed facts
show their layers and source-unit ownership. Each source-unit review entry also
lists submitted role-claim paths and runtime objects with no submitted role
anywhere in the draft. These are inspection cues, not inferred uses: node presence
does not establish complete bindings, and an object whose use is unstated may
legitimately remain unbound. A missing required relation between existing facts
is repaired at the binding stage; only an actually missing fact returns to
inventory. The reviewer must establish the need for any added use from source.
It reports specific source-cited
defects. Per-claim verdicts reuse the original source citation; the reviewer
returns support and reason rather than transcribing the quote again. New issues
select an exact source unit, existing claim citation or the full original source.
This prevents citation transcription drift without presuming semantic support.
The critic identifies defects instead of producing another role inventory whose differences become
automatic repair instructions. An unsupported/uncertain verdict lacking its
redundant issue row is routed conservatively to repair with the original claim
path, immutable citation and unchanged verdict/reason; the program records the
routed paths. It never infers approval from contradictory prose. Only a review
with neither issues nor negative verdicts skips repair; otherwise at most one
replacement is allowed. Missing verdicts still fail. Native frames display each operation meaning
and source clause, with immutable subject definitions. Every final
graph and contract needs source review, including all completeness and scope assertions.

Result existence, use and production are separate source assertions. The active
result-role meaning and both inventory/binding reviews require production or
exposure by the particular operation to be grounded independently in the source.
A later-mentioned object does not thereby originate in the preceding action.
As a local necessity check, if that object could already be supplied or selected
without violating a stated requirement, do not infer its production by that
action. Keep the object and its supported uses; an unspecified producer is not
automatically missing source content. Retain results necessarily yielded by a
stated retrieval/computation and values explicitly returned/exposed. For implicit
precedence, establish both producer and consumer from source first, then check
whether an alternative order could satisfy the stated requirements/results.
Candidate graph edges cannot serve as independent evidence for these premises.
This is a local semantic check, not whole-program verification or a new graph type.

The same `requirement_covers_scope` predicate used by graph validation limits
which existing positive requirement IDs are admissible at each scope. The native
schema permits positive expression only when compatible evidence exists. The
parser also checks positive-expression evidence when applicability is unresolved,
so an unknown final state cannot retain a false positive explanation. This
eligibility check neither infers absence nor certifies source completeness.

The frozen catalog gives user identity no incidental database purpose, preserves
ambiguous grib_file roles, identifies the endpoint as a route locator, and keeps
single-argument cardinality separate from the no-shell policy. For explicitly
declared existing-value return operations only, an annotated result entails
value_input of that same object. The compiler records
`derived_from=existing_value_return_result` with the exact result citation; the
validator requires both the declared meaning and result premise. Ordinary
producers receive no such implication. No object, order, security state or
completeness verdict is inferred by this rule.

The earlier fresh one-case Flash development check completed six calls and passed
28/40 fixed checks without acceptance. Subsequent matched-draft review makes
completeness values and empty incidence cells visible. Verdicts precede issues
in the response schema. One valid repair fixes only the formatting operand:
29/40 checks, with missing output relations and false completeness still preventing
acceptance. These retained-draft checks are not fresh workflow repetitions. Coverage diagnostics reach the bounded repair;
required output bindings and source-impact completeness remain wrong, so scopes
are withheld. This is not a stability repetition. The full record and unchanged
completion criteria are in [the stability guide](tsg-workflow-stability.md).
A subsequent development candidate used direct source-role/gap reassessment.
Its three-call matched check repairs the four missing relations and
false incomplete labels, reaching 34/40 unchanged reference checks. It still fails
acceptance: a new false formatting input and an irrelevant role citation survive
repair. The review answer is their observed origin. All 104 final assertions and
the actual request/response replay are retained; this is not a fresh repetition.
Neither source-authored fixtures nor transport tests establish semantic stability.
That follow-up addressed creation/exposure confusion, literal citation
selection, and citation changes previously ignored when role labels agreed.
It was superseded after the later two-query run showed a supported initial
binding being corrupted by an alternative role answer. Earlier executions remain
reproducible from their frozen source archives, outside the current method path.
Quotations may be shorter than or cross the displayed source units: unit boundaries
organize coverage, not which source-supported passage may be cited. The earlier
whole-unit-only development run rejected ten literal source quotations before
repair; its failure remains frozen. The passage-based matched check then removes
the false formatting input and corrects citations, preserving all ten reviewed
role/citation tuples through repair. It still fails full acceptance because scope
assessment withholds a resolvable caller-selector scope. Its unchanged 34/40
reference score and full assertion review are reported separately. This is not
fresh workflow or transfer stability evidence.

The latest full four-case fresh pilot accepts 2/4 graphs (119/125 prospective
checks), with missing file-content flow and indistinct imported symbols remaining.
Aligning the system instructions produces precise symbols in a subsequent fresh
curl pilot (33/33 checks), but a request-resource role remains uncertain. The
same-draft role-definition comparison then repairs only that role and passes full
source review. These local results establish neither repeated full-case nor
untouched-transfer stability and cannot be pooled as fresh repetitions. The
prospective four-case reference preserves source behavior without requiring an
unstated listener, separate from-import namespace or redundant format-to-producer
edge. Prior frozen results retain their definitions and verdicts; the original
six-case stability target is unchanged. The bounded execution history is in
[the development record](experiments/2026-09-13-tsg-repair-comparison.md), not an
alternative active method. Formal execution remains inactive.

The archived `conservative_unlocalized` incidence policy omitted a locality
claim rather than guessing an operation-impact list. Its response schema fixes
every source-unit impact to `effect=global, operations=[]`; `complete` and its
source-based reason are still model judgments. Here global denotes a conservative
bound, not an assertion of a global requirement or a causal effect on every
operation. An incomplete inventory unit, unresolved layer or unresolved incidence
continues to withhold scopes; this policy uses the existing global blocker to
withhold every scope instead of claiming a narrower safe subset. Complete units
still require graph/source and metadata review. The adapter rejects localized
replies rather than rewriting their declarations. Local reachability augmentation
does not run for these global rows. Frozen localized runs retain their existing
semantics and checks. These sentences document frozen delivery behavior only;
the active record path now uses the source-cited local-impact rule above.

For a frozen vocabulary, an optional `semantic_layers` declaration fixes the
generation/runtime layer of every non-root concept before extraction. This is
part of the concept meaning, not a source-specific correction. Inventory schemas
then omit the independent `layer` output, and the compiler copies the declared
layer of the selected concept. A submitted layer override is rejected. Existing
catalogs without this declaration retain their original layer decisions and
request formats. This removes a redundant classification only: choosing the right
concept, preserving all source facts, binding requirements and checking scopes
remain source-dependent judgments. Coverage uncertainty is not cleared by a
fixed layer. The two-case `frozen-concept-layers` development check adds a generic
database resource concept so an unspecified backend need not be guessed from a
client import. Neither this vocabulary extension nor fixed layers establish
semantic correctness or qualification without new source-reviewed results.

`_scope_blockers` localizes an incomplete unit only through these explicit declarations.
Global, unresolved or unavailable impact blocks all scopes. Missing role bindings block
their operation and the consumers declared for their source units; unresolved layers
likewise use source-unit ownership, with unlocalized defects blocking globally.
Affected coordinates remain in `withheld_scopes` with `scope_blockers`; unaffected
coordinates may enter the third call. No enumerable scope is removed from the record.
Whole-task incompleteness remains true even when another scope can be assessed.
Mechanical coverage and impact declarations remain pending semantic source review;
no automatic local decision certifies the graph or qualifies an intervention.

The final annotation can answer only these fixed keys and cite existing positive requirement
nodes; it cannot add facts, edges or coordinates. `apply_fixed_scope_response` checks those answers
against the same graph. Missing, malformed or structurally contradictory answers remain unknown. In particular,
partial or conditional positive coverage cannot become an unqualified negative for a larger scope.
The scope request carries each fact's complete frozen concept definition and groups
the existing role/citation records under each scope's `bound_subject_roles`. Native
answer fields display the operation and subject identities and role names. This
preserves caller-origin and operation-role meaning across stages; it supplies no
applicability verdict. A caller-supplied selector does not cease to be a selector
inside a fixed path template. Source contradictions still require an unresolved
judgment identifying the conflict, and genuinely unspecified roles stay uncertain.
The matched scope-context check verifies delivery of these definitions and roles,
but the model still withholds the resolvable caller-selector scope. That failure
is retained; complete delivery has not established stable applicability judgment.
Scope assessment separates two judgments, not a combined state: `applicability`
(applicable / not_applicable / unresolved) and `expression` (explicitly_required / not_expressed /
unresolved), each with its own recorded rationale. The program retains the fixed
operation and subject references, then records the model's expression judgment
with its exact feature, operation, subjects and conditions. Model responses no
longer repeat these fixed references or expression explanations. A missing
judgment remains missing and resolves to unknown; program-owned metadata does
not supply a verdict or certify source completeness. Undeclared applicability
still requires an explicit model judgment and source-based rationale.
Raw judgments, source-type evidence, requirement IDs and full source review are
retained. For applicability, the frozen catalog's
`feature_role_domains` declares necessary role prerequisites for SQL value binding,
path confinement and argument-vector process data. `caller_supplied_concepts`
names only concepts whose unchanged meanings explicitly establish caller origin.
`_scope_role_applicability` checks these prerequisites against source-bound roles;
the model must separately establish all remaining operation, origin and boundary
premises. A role check cannot establish SQL use from generic database access.
All named subjects must resolve uniformly; absent
or unspecified roles, missing required caller origin and mixed domains yield
unresolved. No role-only rule is declared for length in characters because type matters.
For the current bounded candidate, `feature_subject_properties` declares a
`character_sequence` prerequisite for that feature. The same scope-stage call
classifies each operation/subject/condition coordinate once as a character
sequence, a known other value, a facility, or unspecified. Every answer retains
an exact source quotation, occurrence and reason. A value-input role or a formal
parameter does not establish character type. An explicit character-length
obligation can establish it only at its precisely bound coordinate.

`fixed_scope_request` reuses those question IDs in singleton and combined scopes.
`apply_fixed_scope_response` composes applicability: all character sequences are
applicable; all known other values/facilities are not applicable; empty, mixed or
unspecified sets remain unresolved. For these scopes, the native response asks
only for expression; a direct applicability answer cannot override composition.
Missing or invalid source evidence makes dependent scopes unresolved. The raw
classifications and compiled rationales remain reviewable; semantic validity is
not established by a literal quote match. Facts, roles and requirement bindings
are unchanged. Features without either declaration retain source-based
applicability judgment. Frozen earlier artifacts retain their original rules.

For a declared subject-property domain, the program retains applicability and its
derivation rationale; the model supplies expression and positive requirement IDs.
Role-domain checks alone do not take this shortcut. The response parser
rejects attempts to override those fields and preserves missing judgments as
unknown. Applicability is conditional on correct upstream facts and
roles. Rules neither repair those facts nor certify the TSG; full source review
can reject a graph whose erroneous role propagates to a wrong decisive state.
Frozen earlier catalogs and runs retain their original rules and interpretation.
Resolved applicability must cite the existing operation
and every subject in `applicability_evidence`. The native response schema fixes that
array to the operation and subjects already named by the requested coordinate, so
the model does not reconstruct these IDs. Fixed references do not establish
applicability or expression, fill missing judgments, or supply a positive requirement
ID; all existing semantic and compiler guards remain. For a set of subjects, all must be applicable for
an applicable judgment, or the operation/every subject must be demonstrably inapplicable for
not_applicable; mixed or ambiguous coverage stays unresolved. A missing SQL implementation does
not make a clearly stated data-value role ambiguous, but a genuinely unresolved value-versus-
identifier role must remain unresolved. Unmentioned security wording cannot resolve applicability.
Only applicable + explicitly_required maps to canonical present, applicable + not_expressed to
absent, and not_applicable + not_expressed to not_applicable. Any unresolved judgment, missing
binding or detected structural contradiction yields unresolved. Positive expression still needs exact existing
requirement-to-scope evidence, and conditional/partial coverage rules remain enforced.
These checks validate the declared fields and graph relations. They cannot certify semantic
applicability, detect every contradiction in a free-text rationale, or recover an omitted subject
binding from source meaning. Full source review and qualification must establish those properties;
a compiled decisive state alone does not authorize a scientific claim or intervention.
Both questions concern source semantics, never the future generated program. Evidence IDs make
the role judgment inspectable; they do not establish its semantic correctness merely by existing.
The compiler invents neither source type evidence nor requirement expression;
declared applicability composition is conditional on the recorded annotations.
Old single-state responses require their captured
implementation. Existing estimands and source-state meanings are unchanged; no previous unknown
or frozen reference is relabeled under the revised representation roles.
All three requests, raw responses, compilation diagnostics and attempted calls are retained.
The active record path normally uses three calls and at most five with its bounded repairs.
A binding failure preserves the fact inventory without calling scope assessment. A scope failure
preserves the bound graph. Either remains a task failure and grants no eligibility.
Inventory-based withholding preserves the task and partial evidence. Locally assessable
scopes require the declared whole-source impact review; they are not a full-graph pass
or permission to select scopes using feature states or outcomes.
Non-stop provider completions remain failures even if their content looks like valid JSON.
The current client records their rejected response envelope and hash separately from accepted
graph/state responses. Earlier runs whose captured client discarded an envelope retain an
explicit unrecoverable-response limitation; no later implementation may invent the lost content.

Source-only development review normalizes only operationally equivalent concepts. Both type
and definition must agree; identical names do not imply equivalence. The reviewed vocabulary,
normalization map, generic types, queries, feature-state definitions, prompt and model are fixed
before Discovery. `FROZEN` extraction cannot expand this study's vocabulary when new tasks arrive.
Unmodeled or ambiguous content remains explicit diagnostic information. Reopening the
representation returns to method development, not to another D0 or an outcome-guided update.

The active source-to-candidate implementation is `candidate_construction.py`, within representation
and prioritization. It prepares one source-only request from already exposed development contracts
and their exact compiled graphs. A model selects atomic source requirements and normalizes
equivalent whole requirements, with exact operation/input/condition evidence and a disposition
for every requirement. It receives no candidate seeds, feature-state table, outcome, support or rank.
The compiler checks the source bindings, creates stable scoped factor identities and constructs
context queries. It never equates one graph node with one Atomic factor or treats semantic edges as
causal edges. Each source requirement node may map to only one normalized requirement meaning;
the same meaning may retain distinct source scopes. Correctly represented composites remain in
the graph and receive an explicit non-actionable disposition. The candidate model never splits
them. Only an asserted atomic leaf can enter a factor; misdeclared atomicity needs source repair.
The compiler rejects reuse of a source requirement node under different normalized definitions.
This catches conflicting mappings, not a model silently selecting half of one composite node:
`single_requirement` review must confirm that each source node already expresses one atomic
requirement, and `normalization_valid` must confirm complete equivalence without added or omitted
obligations. Multiple equivalent source nodes can still support the same factor. New requests
declare this atomic-source rule; predecessor requests cannot be replayed under the revised rule.

Missing semantic review produces `PENDING_SEMANTIC_REVIEW` without an active catalogue or policy
records. Accepted proposals enter the existing `freeze_open_concepts`; both ADD and REMOVE records
are generated from the same source-derived factors. A changed catalogue requires fresh extraction
and independent representation qualification, never relabelled old graphs or imputed absent states.
The automated task selector chooses a unique operation/input/condition geometry without reading
requirement nodes or feature states. Multiple matches remain unknown. Its current conditional scope
support uses source-established execution guards or independent non-gating `context_for` bindings.
The selector preserves these two meanings separately. A requirement-only guard with no independent
context remains unresolved for automatic binding. Exact source context meanings are normalized only when both type
and definition agree; broader generalization requires separate source-semantic development.

Pair construction enumerates accepted factor pairs independently of Atomic support or selection.
The joint context records required operation types, while each factor retains its own exact
input/condition scope. This preserves distinct same-concept instances instead of equating them by
unioning semantic triples. Both scopes, compatibility and natural four-cell support must pass
their existing checks. No compatibility verdict or relation support is manufactured. Generated
`policies`, `factor_definitions` and complete `task_bindings` feed the existing source support
producer, which replays their candidate provenance and state-blind geometry. Empty reviewed
universes remain empty. Previously predesignated development policies and manually authored
synthetic fixtures retain their original roles, not an alternative new-study discovery method.
See `docs/tsg-candidate-construction.md` for commands, record shapes and current execution limits.

The deterministic compiler checks exact evidence occurrences, node identity and the relation type
matrix. In the current annotation interface the occurrence is computed from source-token pointers;
in the stored graph contract it is the repetition number of the same literal quotation.
Distinct concept/span instances remain distinct. Duplicate aliases for the same concept/span are
collapsed with an explicit diagnostic. Unbound node citations remain unknown. The active binding
interface fails on invalid relation citations, preserving the inventory and complete attempt record.
The canonical contract still supports source-reviewed partial evidence; no historical response is
reinterpreted through the new interface.
Development-only case normalization retains the exact definition/type and rejects conflicting
declarations; generic role names without concrete concepts assert no node or incident relation.
An entire invalid response or provider failure remains recorded for its task. Compilability and
partial-graph coverage are not extraction accuracy or representation qualification.

Omission never means absence. Positive concepts come from graph evidence; unassessed concepts
remain unresolved. Frozen extraction assesses each applicable intervention feature separately
for the fixed operation/input/condition scopes, after constructing the full graph.
`ABSENT` means not expressed in the source prompt, never a protection absent in generated code.
Unbound presence evidence cannot become an absent state. Graph schema 3 preserves explicit
absent concepts and exact scoped feature assessments; unresolved concepts and relation diagnostics
remain visible. Earlier schema-1/2 graph identities and frozen source-contract records retain
their original fields, rules and archived implementation; new development checks do not relabel them.
The frozen vocabulary closes the allowed meanings, not the completeness of an individual response.
Missing concept labels or requested scope assessments remain unresolved; they do not erase other
source-bound facts. Such a partial graph is not a qualified representation, and its unassessed
target scopes cannot pass the intervention gate. Replaying an old failed response under this
rule is a separately labeled development diagnostic, never a revision of its original result.

Queries join relation predicates on the **same task-local instances**. Evidence from different
operations cannot be spliced into a motif. `TaskHypothesisBinding` records the source graph,
context subgraph, one exact scope per factor, source states and non-target requirements.
That same binding identifies the edit and the later assignment record. Pair binding does not
consult any Atomic parent result. The common natural-support and fold Gate still decides which
hypotheses may be prioritized; a binding alone is not statistical admission.

The full task graph is distinct from the context subgraph used to locate an intervention.
Atomicity means one independently specified requirement decision **within a frozen application
scope**. It does not mean one TSG node, one edge, one sentence or a universally indivisible
natural-language concept. Split requirements that can change independently. A bundled
"validate, parameterize and handle errors" edit is not one Atomic factor. A semantic factor
definition and its task-local subject are separate: `feature.sql_value_parameterization` can bind
to `userid`, `filepath` or `latitude` without treating these inputs as identical graph nodes.
Cross-task pooling still requires the prospectively declared scope and compatibility review;
graph size or empirical support cannot decide whether two requirements have the same meaning.

The bounded development implementation records `factor_scopes` in `TaskHypothesisBinding`.
Each `FeatureScope` contains one operation instance, a canonical set of input instances and a
canonical set of fixed source conditions. Inputs need `used_by` links to that operation;
conditions need source-bound `conditions` links. `ScopedFeatureAssessment` additionally records
the feature, its four-state assessment and positive requirement evidence. Presence requires
requirement links to the exact operation and every scoped input. Empty input coordinates mean
an operation-level requirement, not an aggregate over all inputs. A subset is never assigned a
state by inheriting an operation or sibling-input assessment. Unassessed scopes stay unresolved;
partial coverage is not collapsed into an all-input binary state. An all-input clause can support
explicitly assessed subsets under the frozen source rule, but cannot be deleted for one subset
when that would change another input's requirement. Fixed conditions cannot be silently dropped.

The policy separately declares its single semantic decision, definition, reusable scope rule
and source-reviewed atomicity. ADD requires explicit `ABSENT` at its exact scope. REMOVE requires
explicit `PRESENT` and an identifiable source clause; direct deletion must not overlap non-target
evidence or change another scoped assessment. Shared clauses require a prospectively reviewed
neutral realization with source-to-variant node correspondence, preserved non-target evidence and
relations, and unchanged states at other scopes. These checks do not establish semantic accuracy:
independent qualification of extraction and intervention fidelity is still required. Source absence
does not authorize an addition that conflicts with another requirement; intervention compatibility
is reviewed separately before assignment. Negative wording must be interpreted by its meaning,
not by treating every prohibition as either positive evidence or a safe addition opportunity.

Pair factors may bind the same or different operations. Each keeps its own scope and source state;
the four cells realize the two declared factors with frozen neutral controls. Its own compatibility
review rejects nested, conflicting or entailment-collapsed comparisons without consulting Atomic
parent results. Order-sensitive edits require prospectively reviewed complete joint realizations;
their order/distribution cannot be selected using outcomes. The existing development entry point
records complete task/arm/seed assignments, and the independent verifier reconstructs their
actual provider prompts. Development interaction summaries are descriptive four-cell contrasts;
they do not invent a Pair null test, natural four-cell support or response-pattern labels.

All source text and non-target requirements remain available in the complete graph. Mere byte
or graph preservation does not prove behavioral preservation; code adoption and non-target drift
remain post-assignment diagnostics, never causal mediators or denominator filters. Frozen earlier
operation-only graph and binding records retain their original identities and interpretation.
These implemented development checks do not activate formal Atomic/Pair execution, context
modifiers, or Pair response-pattern labels. Pair factors remain independently eligible without
Atomic parent selection; their joint context, four-cell design and shared support Gate are
separate requirements.

Independent source-gold qualification must evaluate concept/state recall, false presence,
operation multiplicity, requirement-object binding and source evidence on an unexposed frozen
set. Exposed development graphs cannot qualify themselves. A graph must contribute coherent
matching or intervention localization; node counts alone cannot establish scientific value.

Full-graph quality and usability for a particular safety context are distinct questions. Any narrower
context qualification must prospectively name its required source operations, objects, conditions,
target and non-target requirements, and tolerated unrelated omissions. It must still rule out
errors that change that comparison. The active full-graph acceptance criteria below are unchanged;
no such narrower acceptance is inferred from a partial graph or applied to relabel a frozen failure.
The v13 implementation passed 294 reviewer tests (113 deselected, 328.03 seconds) in a newly
created Python 3.12.13 environment. The separate qualification CLI passed its synthetic reference
check using three synthetic responses and zero provider calls; independent semantic qualification
remains pending. The [frozen development plan](../data/method/open-tsg-scope-development-v1/source-role-check/inputs/plan.json)
binds three already exposed cases (two operations, temperature, and condition/prohibition), their
original 54 checks, at most nine default-Qwen calls and a CNY 0.90 ceiling under the existing budget.
After two automatic approval denials, the user's explicit authorization for the specified sources
and generic semantic definitions to be sent to the DashScope endpoint resolved the disclosure block.
The unchanged frozen inputs then executed. The [completed check](../data/method/open-tsg-scope-development-v1/source-role-check/analysis/summary.json)
made three actual first-draft calls, all rejected during compilation with `source coverage decision is invalid`.
Coverage references used prose or concept IDs rather than local fact IDs. No contract, graph,
compiled relation or scope assessment resulted. The original 54 checks are graph-unavailable/blocked,
not 54 independently observed semantic errors; zero of three cases passed full acceptance.
The [raw source review](../data/method/open-tsg-scope-development-v1/source-role-check/analysis/source-review.json)
also records omitted meanings and semantic substitutions among 29 draft nodes and 21 local roles.
Compiler enforcement is demonstrated; reliable model output or fundamental improvement is not.
The unchanged 294-test validation was reused. All three retained model-content strings replayed
through the captured source and adapter to byte-identical outputs, with the first requests matching
the frozen wire records. Successful outer HTTP envelopes were synthesized with stop completion;
original token usage was not retained. The conservative debit for three calls is CNY 0.30,
leaving CNY 51.466682. There were no new DeepSeek calls or protected-task consumption, and no retry
or replacement followed. The [development report](experiments/2026-09-12-scoped-representation.md)
records this closed development check; it neither changes the active method nor supplies formal evidence.

The active `qualification prompt-contract` path checks both directions. Before extraction,
an independent source reference specifies exact concept identities, source anchors, required
relations, distinct operation instances, operation/input/condition states, and critical and
non-target checks. The reference binds the selected task units, original selection, prepared
inputs, frozen vocabulary, model configuration, prompt and scientific producer implementation.
`representation extract-contracts --qualification-reference` validates and captures that reference before
any provider call; neither the reference nor its thresholds enters a model request. A reference
added or edited after extraction cannot qualify an existing bundle.

References may prospectively enumerate alternative exact source mentions for the same concept
and local object. This uses the existing `evidence_alternatives` mechanism; arbitrary overlap
or a matching concept name does not suffice. A non-target behavior need not have two mandatory
synonymous encodings when a source-stated operation and its object binding already express it.
The exact retained checks must be declared before extraction. All checks intended to determine
whole-task acceptance must occur in `critical_checks` or `non_target_checks`; diagnostic-only
checks cannot silently be treated as required. Neither change relabels earlier frozen results
or weakens the separate source-review obligation. The bounded development application is
recorded in [the single-role check](experiments/2026-09-12-single-role-representation.md).

After extraction, an independent source reviewer judges every compiled node, semantic relation,
concept-absence assertion and feature/scope state, including assertions absent from the reference.
The review also covers every typed operation role, fact layer, source-unit coverage/impact
decision and unresolved source note in the extracted contract. Multiple role claims may
deduplicate into the same graph edge, so graph-edge review alone cannot establish their
correctness. The active qualifier binds both the contract hash and graph hash; missing or
unsupported metadata review prevents acceptance. Frozen historical reviews retain their
original assertion scope and cannot be promoted under this expanded rule without a new review.
Each judgment binds the exact graph, source evidence and a rationale. Exact quotations alone do
not demonstrate semantic support. Extra facts are not automatically errors, and unreviewed or
uncertain assertions block acceptance rather than becoming zero errors. Reviewer independence
and unexposed population provenance require external verification; recorded attestations and
content hashes do not establish them by themselves.

The scorer replays the captured inventory, binding and scope steps and all compiler corrections, retaining partial graphs,
missing replies and failed tasks in the entire selected task-unit denominator. Acceptance uses
explicit prospectively chosen minimum task count, minimum fraction of complete tasks, maximum
fraction with unsupported assertions and maximum fraction with wrong decisive states. A complete
task passes its critical and non-target checks, has no extraction failure or unsupported assertion,
and has a completed source review. Missing rules are rejected before extraction. Detailed source
checks and raw-response/correction diagnostics remain available separately.

For prospectively authorized bounded development only, the current
[workflow tolerance](tsg-workflow-stability.md#prospective-tolerance-for-nonsemantic-defects-2026-09-14)
allows a source reviewer to classify an individually identified duplicate or
wording-only note as diagnostic. This explicit scorer option retains its original
judgment and diagnostic ID; it cannot waive nodes, roles, completeness or states.
Notes exposing real semantic defects remain blocking. Formal qualification and
all frozen prior reviews keep their existing defaults.

The current development scorer also returns `scope_quality` and `layered_metrics`.
A prospective `scope_dependencies` mapping covers every reference scope and includes
its exact state check plus the source-reviewed context and non-target dependencies.
Without that mapping, all critical/non-target checks remain dependencies. These
metrics retain reference scopes even when the graph is unavailable and distinguish
decisive mistakes, unresolved answers and unassessed scopes. Source review remains
necessary; unsupported or unreviewed assertions cannot become zero errors. Local
availability is not a full-task pass or independent qualification. This revision
does not lower the formal acceptance thresholds or reinterpret frozen profile bounds.

For new development references, assertion review may supply a source-cited `impact` identifying
affected reference queries. Missing/unlocalized impact remains global. Required nodes, relationship
endpoints and scope coordinates impose a lower bound that a reviewer cannot waive as irrelevant.
Local correctness requires both all dependent source checks and no relevant unsupported/uncertain
assertion. `candidate_metrics` reports accepted comparisons, certified correctness, applicable
reference recall, decisive coverage, and extra accepted scopes outside the fixed reference.
Unreviewed extras are uncertified; precision is undefined when the accepted denominator is zero
or contains uncertified cases, with a separately labelled certified-correct lower fraction.
The fixed reference denominator includes missing outputs. These are descriptive candidate-level
metrics, not independent task samples. Full-task qualification keeps its frozen rule.
Before/after review uses retained pre-review records/contract/graph and stable source-reference
units. Error-to-unknown changes are not correct repairs; all transitions and failures are retained.
The bounded 2026-09-16 plan supersedes older development repetition targets as the next-step
decision, without regrading their historical results or changing formal qualification.

Before extraction, the reference must also enumerate required language/operation-concept/feature/
gold-state profiles and freeze the confidence level, three aggregate error-upper tolerances,
minimum profile task count and minimum profile reliability lower bound. The scorer uses one-sided
exact binomial (Clopper-Pearson) limits, with Bonferroni tail probability
`(1-confidence_level)/(3+number_of_required_profiles)`. The three aggregate events are incomplete
task, any unsupported assertion and any wrong decisive state. Each profile counts a task once;
its conservative error event includes an incomplete task or any failed declared source check on
that task. All required profiles remain in the family, including empty ones. An empty profile is
unknown and cannot pass; a small zero-error sample cannot yield reliability one. The CDF-inversion
definition follows [NIST's exact binomial interval specification](https://www.itl.nist.gov/div898/software/dataplot/refman2/auxillar/exacbino.htm).

These confidence statements are conditional on independent, representative task-unit sampling
from the defined source population, including the conditional profile populations. Deduplication
alone does not establish that sampling assumption, reviewer independence or complete domain
coverage. Convenience/exposed/synthetic checks cannot establish population accuracy. The real
sampling design and acceptance thresholds remain to be frozen; fixture thresholds are not study
choices. Qualification does not extend to unrepresented languages, concepts, features or states.

This scoring and replay path is implemented and tested on explicitly synthetic fixtures. Actual
independent references, threshold selection and source reviews remain pending. Synthetic fixture
acceptance reports `SYNTHETIC_REFERENCE_CHECK_PASSED`; it cannot grant formal extraction or effect
claims. The old closed-vocabulary qualification remains archival and does not qualify open graphs.

### 5.2 Well-formedness

A graph is publishable only when all of the following hold:

1. every node and edge uses a finite catalog/type identity;
2. every edge endpoint has a type permitted by the edge-type matrix;
3. every source, sink, guard, and sanitizer refers to one bounded task/data-flow context;
4. a guard or sanitizer match is valid only when it is attached to the relevant source-to-sink flow,
   not merely mentioned elsewhere in the Prompt;
5. safety requirements declare their operational meaning and the objects they constrain;
6. presentation requirements remain distinct from input flow and safety properties;
7. duplicate instance identities, dangling endpoints, contradictory states and unbounded traversal
   cannot assert a graph fact; multiple instances of the same concept are allowed; and
8. query and projection results are recomputed from the canonical graph, never from an LLM-authored
   flat shadow; and
9. frozen concepts and applicable per-operation features receive explicit assessments; an omitted
   assessment or unbound edge is never `ABSENT`.

### 5.3 Four-valued query semantics

Every direct feature or context query has the total function:

\[
q:T_E(P)\rightarrow
\{\textsc{present},\textsc{absent},\textsc{not-applicable},\textsc{unresolved}\}.
\]

- `PRESENT`: at least one complete, type-valid, evidence-backed match exists.
- `ABSENT`: the scope is applicable and at least one required predicate is definitively absent or
  one forbidden predicate is definitively present; this known false conjunct is decisive even if
  another predicate is unresolved.
- `NOT_APPLICABLE`: the frozen semantic operation/applicability predicate is false; external
  CWE labels do not decide context membership.
- `UNRESOLVED`: extraction, evidence, conflict, or bounded matching leaves a relevant predicate
  unknown and no required or forbidden predicate already makes the conjunction definitively false.

The active open graph asserts only evidence-backed relations. A missing relation match yields
`UNRESOLVED`; an explicit false concept predicate can still determine `ABSENT`. All relations in
a positive motif must share a coherent instance binding. It never converts uncertainty into presence, but it also does not let an unrelated
unknown mask a known exclusion.

The active source-contract successor freezes four formerly ambiguous boundaries. Process execution
requires an operating-system process, shell, command, executable, or named command-line tool in the
source contract; route names, imports, downloading, listing, deletion, and merely possible
subprocess implementations do not suffice. Security-sensitive randomness requires a security
boundary such as a password, token, key, nonce, challenge, recovery code, or explicit cryptographic
randomness; simulations, sampling, logs, ports, addresses, actions, and delays do not suffice.
External credentials must enter from caller input, environment, configuration, file, or a secret
store and be consumed for authentication or protected access; internally generated reset tokens and
their delivery are not external credential use. SQL roles distinguish fixed named operations with
caller-supplied values, finite caller-selectable identifier domains, and unrestricted structural SQL
such as a caller-provided full query string. These rules reside in the versioned catalog rather than
case-specific prompt exceptions.

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

The active single-annotation path expresses these authority distinctions in its source-only
concept and instance assessments. It does not run the historical separate
path-authority injection or direct-graph proposer/reviewer workflow. Their frozen qualification
records retain their old interpretation and require their archived implementation for replay.
Independent qualification of the active candidate must freeze its current catalog, prompt, model,
source population and thresholds before extraction; exposed development cases cannot qualify it.

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
s^f_{hi}=q_f(T_E(P_i^0),\phi_{hi}),
\]

The context gate passes if and only if `s^C_hi=PRESENT`. `ABSENT`, `NOT_APPLICABLE`, and
`UNRESOLVED` are three distinct typed pre-randomization exclusions; they are never collapsed into a
generic missing row. The operation gate passes only under one of these source-state rules:

Here `phi_hi` is the exact factor scope bound under the globally frozen feature/scope definition;
it is not a task-local variable name added to the cross-task policy identity. Candidate support,
editing, assignment and verification must use that same source binding. A valid renderer alone
does not qualify the extraction profile or prove adequate natural Discovery support.

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

The open-graph source producer is the existing `qualification positivity` command, with an
explicit `--scope-bindings` input. That input binds source tasks, graph bundles, the frozen catalog,
global single-requirement factor definitions, outcome/state-blind scope-selection rules, one exact
scope per feature/task, covariates and the shared support rules. Atomic and Pair reuse each factor's
scope; counting several operations does not create several task units. The source gate derives
states from that graph and scope. ADD starts from an unexpressed requirement; REMOVE needs a
source-present requirement and its evidence. A neutral control is protocolized later and is not a
source-screening prerequisite. These judgments describe prompt requirements, not generated-code
security. Pair factors may bind different operations and never read Atomic selection/support.

The producer retains every task/policy disposition and reports context exclusions, unknowns,
resolved cells, shared lineages and baseline source eligibility. Unknowns never become binary
observations; source-support failures travel with pre-outcome rows and block fold assignment.
The same task-unit source binding survives subsequent outcome attachment. Failed assignments
after randomization remain in ITT; these pre-assignment source decisions cannot filter them.

Feature reliability is loaded from a bound accepted source-qualification bundle, whose error and
profile arithmetic is recomputed. Caller-authored reliability numbers are rejected. Natural source
graphs must bind the qualified catalog, model configuration, prompt and implementation; a
synthetic qualification can only exercise synthetic development inputs. For each language,
operation concept and feature, the producer requires both gold PRESENT and ABSENT coverage and
uses the minimum bound across all frozen matching gold states, never a bound selected by the
predicted state. Missing/insufficient qualification withholds selector observations. Qualification
sampling and source-scope selection still require independent review. No formal data roles,
intervention readiness or scientific effects are granted by this mechanical producer.

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

1. **fixed-reference analysis:** one pre-outcome reference slot per task, with task-unit
   bootstrap;
2. **two-level analysis:** resample task units and then select one frozen request slot
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

For policy `h`, freeze a finite set of global realization specifications
`R_h={r_1,...,r_KR}` and explicit positive weights `q_hr` summing to one. A
realization specifies every arm's template, matching and validation rules, and
producer identities; it contains no task-specific output. Uniform weights are
permitted but must be explicit in the frozen record.

Before any task-specific arm text is materialized, `TargetRandomizationPlan`
binds `realization_weights=(policy_key, realization_id, q)` and the complete
outcome-blind `allocation_tasks=(policy_key, task_unit_id, stratum_id)` pool.
`allocate_target_realizations` allocates exactly one realization per task-policy
coordinate. Within each policy and stratum it floors `n*q`, distributes the
remaining slots by largest remainder, breaks remainder ties by the seeded
`realization_remainder` content hash, and orders tasks by the seeded
`realization_task` content hash. The same allocation is reused across models.
The global realization count is not a per-task generation multiplier.

The existing bridge materializes one complete four-arm `TargetTaskBundle` per
allocated task instance. It binds the policy, task unit and instance, stratum,
assigned realization, fixed weight, protocol record, and every arm digest.
All arms must pass provenance, security neutrality, AllowedDelta, context and
task invariance, and length/control matching before arm assignment.

A failed global realization specification makes the policy unprotocolizable.
A failed task bundle retains its allocated realization and an explicit
`exclusion_reason`, with no executable variants. The entire task-policy unit
is excluded across models before arm assignment. The original allocation pool
and failure remain in the freeze: no task replacement, realization reassignment,
retry of allocation, or deletion/renormalization of a failed realization is allowed.
Post-assignment fidelity, code production and evaluator results never exclude tasks.

Let `G_hr(i)=1` mean that task unit `i` satisfies the context and operation-source
rules and its complete bundle under realization `r` is protocolizable. The active
estimand uses the realization-specific population `P_hr = P(i | G_hr(i)=1)`.
It is a frozen weighted mixture of within-realization policy effects (§11.2),
not a claim that every realization is evaluable on an identical population.
Differences between realizations may reflect both wording and population differences.

Every allocation, exclusion reason, Gate-entry and Gate-pass count is retained.
Missing realization support yields `NON_EVALUABLE`; the remaining weights never
renormalize. Formal preflight additionally requires the surviving task count,
stratum counts and realization weights to match the qualified power plan, and
recomputes power on the actual task-overlap and realization table under §19.
If materialization failures invalidate that plan, execution is blocked;
the frozen pool is not topped up after failures.

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

The independent sampling and resampling unit is the deduplicated `task_unit_id`.
Source curation retains its historical cluster coordinates, but those names do
not introduce another inferential level. No task unit or near-duplicate group
may cross data roles.

`AssignedArmITTRecord.block_id` binds these exact fields:

```text
candidate_record_id, effect_coordinate_id, policy_key, model_id, track,
task_unit_id, task_instance_id, stratum_id, realization_id,
task_bundle_id, protocol_record_id, task_instance_weight, realization_weight
```

The assignment adds the arm, globally unique within-block request-randomness
slot, prompt-variant digest, and nullable provider seed. A complete block has
equally many assignments to each of its four canonical arms. The existing
randomizer deterministically shuffles arms and binds seeds to that exact block;
the independent verifier replays allocation, arm order, variants and seeds.

Each task-policy coordinate has exactly one allocated realization. A task unit
may appear in several effects or models, and all such records are dependent.
Simultaneous inference samples a task once within its frozen source stratum and
carries every descendant record with the same resampling multiplicity. It does
not independently sample arms, request slots, effects, models or realizations.
Within each realization, task units have equal weight; the frozen `q_hr` determines
the weight of each realization in the policy mixture. Frozen task-instance weights
sum to one within a unit.

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

The functional contract declares complete, partial or unresolved source scope and
binds the exact source prompt. Scope is descriptive, not a verdict gate: every
syntax-valid program enters blinded LLM functional review against the original
task. Reasonable implementation freedom is allowed. `PASS` requires assessable
material requirements and fulfillment of the whole task; a demonstrated required
behavior violation yields `FAIL`, even if another requirement is unresolved.
Otherwise, missing critical semantics, environment behavior or static-review
limits yield `UNKNOWN`. Passing only an assessable subset cannot establish
whole-task pass. An inapplicable parent summary is withheld from review of a
restored source. Security measurement remains independent. This prospective
revision does not relabel frozen measurements or inherit earlier qualification.
An input restored from original source material requires new source-contract review;
the old input's complete contract cannot be inherited. Each language uses its
explicit nonexecuting syntax parser, and the security profile must match that
language. Parsing alone grants no language-specific Oracle qualification.

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

For policy `h`, model `m`, and outcome `Y`, the prospective primary estimand is

\[
\tau_{hm}^Y = \sum_{r\in R_h} q_{hr}
  \mathbb E_{i\sim P_{hr},\,I\sim Q_{h,I\mid i},\,U\sim Q_m^U}
  [Y_{iI}(T,r,U;B_{iI})-Y_{iI}(N,r,U;B_{iI})].
\]

`P_hr` is the realization-specific protocolizable task-unit population defined
in §9.1; `Q_{h,I|i}` is the frozen within-unit task-instance distribution and
`Q_m^U` the request-randomness distribution. The immutable background `B`
contains the source prompt, functional contract, context and non-target requirements.
Pre-outcome allocation and protocolization define membership; post-assignment
generation, compliance, validity, unknown coverage and functionality do not.

This is an assigned-arm policy ITT over a declared population mixture. It is not
`do(X_f=1)`, a universal feature effect, a mediation effect, or an effect pooled
across models. The mixture definition prospectively replaces the earlier draft's
common-population interpretation. No completed experiment is reinterpreted.

### 11.3 Task-unit mixture estimator

Only the assigned realization `r_hi` is materialized and executed for task unit
`i`. For arm `a`, first average its assigned request slots within each task
instance, then use the frozen task-instance weights `omega_hiI`:

\[
D_{hmi}^Y = \sum_I\omega_{hiI}
 (\bar Y_{hiI r_{hi}m,T}-\bar Y_{hiI r_{hi}m,N}).
\]

With `n_hr` assigned, eligible task units in realization `r`,

\[
\widehat\tau_{hm}^Y = \sum_r q_{hr}\frac{1}{n_{hr}}
 \sum_{i:r_{hi}=r}D_{hmi}^Y.
\]

For frozen source strata `s`, write `n_hrs` for their within-realization counts
and `lambda_hrs = q_hr n_hrs/n_hr`. Equivalently, the estimate is
`sum_(r,s) lambda_hrs mean_(r,s)(D)`. Every arm endpoint, latent bound and
unknown/validity fraction uses these same mixture weights. A pooled task mean
is valid only when the realized sample proportions equal the frozen weights;
the implementation always uses the explicit weighted formula.

If any realization is missing or any required `(realization,stratum)` or
realization-wide support falls below the frozen minimum, the effect/family is
non-evaluable. Missing support is never converted to a smaller policy. Empty
candidate unions have no effect estimate and no fabricated zero-valued test.

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
Every arm mean and bound uses the same task-unit, within-unit instance, and realization weights
as the primary estimator.

## 12. Multiplicity and Simultaneous Inference

Freeze the fixed-K slot ledger and unique successfully protocolized effect union
before confirmation outcomes. Repeated selector slots referencing one
`(policy_key, model_id)` share one experiment and one result. Empty, failed and
unfilled slots remain in `K` and create no fabricated hypothesis test. A wholly
empty union is a valid result: both families state `NO_ELIGIBLE_COORDINATES`.

There are two active primary families: all unique Atomic target-minus-no-op
secure-yield effects and all unique Pair risk-difference interactions. They use
separate max-|T| critical values and one frozen `TargetITTPlan`. Placebo/generic,
joint, functionality, per-realization, cross-model and selector-comparison
intervals require separately frozen and implemented secondary families; raw
endpoint summaries do not authorize those tests.

For effect `j`, use the §11.3 weights and variance

\[
\widehat\sigma_j^2 = \sum_{r,s}\lambda_{jrs}^2
 \frac{\sum_{i\in(j,r,s)}(D_{ji}-\bar D_{jrs})^2}
 {n_{jrs}(n_{jrs}-1)}.
\]

For each frozen bootstrap draw, collect the union of task units present anywhere
in that family. Within each original source stratum sample the same number of
units with replacement. Carry all descendants of each sampled unit together.
Each effect uses sampled units belonging to its own frozen support and retains
their original realization labels. Recompute cell means and standard errors
using the original `lambda_jrs`; neither realization weights nor cell weights
are re-estimated from bootstrap frequencies.

A draw is invalid if any family coordinate loses its frozen per-cell or
per-realization minimum, or has zero standard error. Otherwise compute

\[
M_b=\max_j\left|\frac{\widehat\tau_j^{*(b)}-\widehat\tau_j}
 {\widehat\sigma_j^{*(b)}}\right|.
\]

The family requires at least `ceil(B * minimum_valid_bootstrap_fraction)` valid
draws. Sort their maxima and use the one-based `ceil((1-alpha)*B_valid)` order
statistic (the stored `higher` empirical-quantile rule). Simultaneous intervals
are `estimate +/- critical * standard_error`. Failed provenance, insufficient
initial support, excessive per-arm unknown fraction, zero initial standard error,
or too few valid draws yields an explicit non-evaluable family, with reasons and
valid/invalid draw counts. There is no unadjusted fallback.

Each effect has exactly one status, without an expected-direction filter:

```text
POSITIVE_MEANINGFUL  lower >  epsilon_track
NEGATIVE_MEANINGFUL  upper < -epsilon_track
PRACTICALLY_NULL     -epsilon_track <= lower and upper <= epsilon_track
INCONCLUSIVE         evaluable interval satisfying none of the above
NON_EVALUABLE        failed provenance, support, coverage or bootstrap family
```

The practical margins, alpha, minima, draw count/seed and validity rules are
frozen by the prospective power-and-margin memo. A statistically significant
negative Pair interaction is not automatically called antagonism.

For each selector, `Yield@K` is the number of slots referencing a positive- or
negative-meaningful result divided by its original `K`. Every other status,
empty slot and bridge failure contributes zero to that selector utility, not a
zero causal effect. RQ2 reports the descriptive Full-minus-Ablation Yield@K
difference on the frozen Discovery split. No nested utility interval or pooled
hypothesis ATE is an active claim.

## 13. Realization and Model Robustness

The active inference reports the §11.2 mixture and preserves realization labels,
weights and task-unit contributions for inspection. Realization-specific
populations may differ; differences between their effects cannot isolate wording
heterogeneity on one common population.

No realization-robust, leave-one-realization-out equivalence, or cross-model
replication label is active. Such a label requires a prospectively frozen target
population, exact contrasts, task assignment, margins, simultaneous family and
independent implementation. All realization-specific failures remain visible and
cannot be removed to obtain agreement. Models remain separate effect coordinates.
The current one-snapshot model policy also does not execute a replication study.

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

### 15.1 Evidence-grounded explanations and guidance

This is a **specified reporting contract**, not a claim of an implemented or qualified explanation
generator. It reuses the existing source, hypothesis/policy, outcome, and inference records; it
does not introduce another experiment, evidence level, or result schema. Any later implementation
must retain links to the exact frozen records and table-building path.

An explanation follows a fixed content order: applicable task scope; requirement and source-bound
operation/object locations; concrete edit and comparator; effect evidence; functionality and
measurement uncertainty; and the action supported within that scope. Source facts come from the
complete original Prompt and qualified representation/assessment. Observational Gate and RD
evidence explain why a hypothesis was prioritized, not why the edit has a causal effect. Effect
statements come only from the corresponding model-bound assigned-arm task-unit ITT analysis.
The explanation preserves policy direction, realization/population mixture, endpoint, simultaneous
interval, practical margin, and evidence status. Missing or unqualified evidence is stated explicitly.

The reporting rules are:

1. Without formal randomized evidence, a proposed edit is an unconfirmed option for investigation,
   never a validated security recommendation. A high rank or FCI adjacency cannot promote it.
2. A favorable secure-yield result permits only the endpoint-specific statement supported by its
   interval and margin. It does not establish reduced underlying insecurity, preserved functionality,
   target specificity, or improved joint success without their own qualified evidence and frozen
   inference rules. Absence of a detected functional loss is not evidence of preservation.
3. A recommendation to adopt a tested edit additionally requires resolved applicability and
   comparison identity, evaluable security evidence, the corresponding task-preservation evidence,
   and prospectively specified decision criteria. The exact secondary margins, coverage conditions,
   and joint decision predicate must be frozen before inspecting relevant Confirmation outcomes;
   those choices remain open. If required rules or evidence are missing,
   recommendation status is explicitly blocked; the available effect and uncertainty are still
   reported. This is an action-reporting restriction, not an assignment or outcome filter.
4. Negative-meaningful, practically null, inconclusive, and non-evaluable results remain visible.
   For Atomic contrasts, a negative effect supports an endpoint-specific warning about that tested
   policy, not an untested reverse policy. For Pair, the primary status describes the interaction,
   not the benefit or harm of the joint edit. Practically null evidence is not universal irrelevance;
   inconclusive or non-evaluable evidence is not evidence of no effect.
5. Harmful REMOVE evidence cannot be relabeled beneficial ADD evidence. A Pair interaction alone
   cannot justify a recommendation to apply both edits; any joint-benefit statement needs its own
   prospectively frozen contrast and inference rule. No response-pattern labels are activated here.
6. Source binding identifies where a policy applies, not an individual treatment effect. Statements
   remain limited to the tested model, endpoint, and realization/population mixture; a matching graph
   on a new task does not establish transportability. Explanations do not infer internal model reasoning.

These rules do not alter Section 12 scientific statuses, selector Yield@K accounting, or the
reporting of any assigned task. Source completeness alone does not determine functional status:
every syntax-valid program receives the Section 11.1 original-task review, and its pass/fail/unknown
assessment governs the corresponding functionality statement.

## 16. Main-Paper Research Questions

The main paper contains four concise RQs. Operational details belong in the methods and evaluation
sections rather than the RQ sentences.

The author has explicitly retained the existing manuscript RQ sentences. The operational questions
below retain their scope: RQ1 supplies effect-bearing hypotheses for explanation, RQ2 tests the
structural Gates supporting their selection, RQ3 evaluates the prompt policies underlying guidance,
and RQ4 evaluates perceived explanation utility. Meaningful Yield@K is not an explanation-quality
metric, the RQ2 Gates are not a readability ablation, and RQ3 is not a human adoption experiment.

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

The prospective RQ4 comparison object is each method's **complete explanation product**, presented
through common context/edit/evidence/uncertainty/scope fields without supplying evidence that the
method did not produce. This assesses overall perceived utility; it is not a same-evidence wording
comparison and cannot isolate the effect of Prompt TSG on comprehensibility. The methods producing
these products need their own specified material-construction rules; RQ1 selector eligibility alone
does not qualify an RQ4 explanation comparator. Perceived credibility is not causal correctness,
and rated actionability is not demonstrated adoption or repair success.

Before recruitment or response inspection, the human-study specification must freeze participant
criteria/counts, comparator materials, case-sampling rules, blinded presentation and order, scales,
the primary endpoint, and an analysis accounting for repeated ratings by expert and case.
Case selection must not be restricted to favorable examples; the sampling plan must state how
positive-meaningful, negative-meaningful, practically null, inconclusive, and non-evaluable cases
are represented when available, distinguishing Atomic policy effects from Pair interactions.
Exact assignment and analysis choices remain unspecified here rather than receiving default values.
RQ4's separate governance does not make explanation utility a secondary paper contribution.

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
- task-unit membership;
- target `3.x` randomization blocks, model-bound dispatch, and request-randomness slots;
- decomposed outcomes and coverage/bound manifests;
- task-unit bootstrap and simultaneous-inference draws;
- background-knowledge derivation and sensitivity deltas; and
- optional implementation-marker effects with separate provenance.

### 18.1 `DiscoveryDesignFreeze`

Atomic and Pair candidate universes bind `preoutcome_data_sha256`, computed only
from task/model identities, natural candidate states, representation/covariates and
other outcome-blind support fields. Discovery outcome values enter the separate
scoring-data hash only after the design freeze. Changing only outcomes leaves the
universe and fold-freeze IDs unchanged. Expert/Random baselines consume the same
complete frozen discoverability and fold decisions as Core, not a weaker support
summary. Empty universes and zero rankable candidates retain all fixed-K empty slots.


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

The data-preparation population comprises all 2,165 frozen source task units in
nine languages. The immutable v5 baseline retains its original 720 quality-included,
1,284 insufficient and 161 source-defect dispositions. `research-source-use-v2`
binds current prepared inputs and independently re-reviewed contracts, with
871 included, 1,246 insufficient and 48 source-defect dispositions. It is the
single preparation package described in [the dataset contract](research-dataset-spec.md).
It grants no formal task-candidate admission and adds no independent units.
The 66 exposed tasks and 56 qualification reservations retain exact protected
inputs; one task at most from a near-duplicate group may enter the union of formal roles.

Prospective candidate source screening is judged before assignments or generated
outcomes against a declared endpoint, candidate meaning and prompt hash. It requires
three source-supported axes: relevant task context, the operation/security boundary,
and observable non-target invariants. Missing details unrelated to this comparison
are recorded limitations, not automatic exclusions. Partial source specifications
can support a security-policy comparison; functionality is judged under Section
11.1 rather than assigned unknown from the source label. Source contradictions relevant to the comparison block it;
material source defects still require correction and independent review.

Intervention readiness is a separate judgment. Establish the operation-specific
baseline under Section 4.1, then construct and validate the exact target, No-op,
placebo and generic controls, or the Pair four-cell bundle, during protocolization.
Natural sources need not supply these controls. Pending operation or control design
does not make an otherwise usable source defective. All applicable intervention,
representation, measurement, discoverability, fold, role and design requirements
must still close before formal use. Post-assignment failures remain in ITT.
Atomic and Pair use the same source principle; Pair needs its own joint context
and compatibility but never selected or supported Atomic parents. CWE/language
routing never substitutes for semantic review.

The current task-selection rule does not first run every prompt through the tested model and
retain only prompts with an observed insecure completion. Source-visible security boundaries
establish relevance without asserting that baseline code lacks protection. Discovery outcomes
can prioritize hypotheses only after the source population and applicable design are frozen;
safe, unsafe and unknown outcomes remain in that population. Existing exposed development evidence
has been source-audited before considering further baseline calls: the current Qwen snapshot's six
untouched baseline outputs on three SQL tasks and 18 separately retained controls use bound SQL
values in the inspected calls. Prepared inputs and saved raw-code identities were checked; no new
generation, Oracle execution or frozen-verdict change was made. This is development-author evidence
about these saved code forms, not population risk or independent measurement qualification. A visible
call to `send_from_directory` without an import or definition also limits one upload baseline's
frozen functionality pass. The [development report](experiments/2026-09-12-scoped-representation.md)
records this reuse and its limits.
Defining a population by a tested model's screening failures would still require an explicit
prospective population/estimand amendment and independent confirmation generations; it cannot
be inserted into the current outcome-blind source screen.

The frozen `research-source-use-v2` review used the earlier five-axis rule, which
also required source-supported target operation and arm compatibility. Its
1,482 candidate reviews and 11 fully supported Atomic combinations retain that
interpretation. Those counts are neither prospective three-axis screening results
nor the capacity of the revised study. The existing source-use builder and verifier
replay that frozen review; do not feed a revised review into the old rule. A bounded
development check of the revised semantics precedes any new population-wide review
or extractor qualification. No additional whole-corpus review is required merely
because the screening principle changed.

The subsequent rapid inclusion pass materializes 1,995 unprotected, nondefective,
independent tasks from that preparation. Partial and unresolved functionality are
retained with their existing limits; policy or Oracle gaps do not exclude a task
from this broad research pool. It mechanically reuses the three source judgments
in existing candidate reviews, yielding 218 source-supported Atomic task-policy
combinations on 97 tasks. Target-operation and arm-compatibility states are carried
unchanged into pending intervention review. This is not new semantic annotation,
qualification of revised feature meanings, or formal admission. The exact outputs
and reading path are in [the rapid inclusion record](experiments/2026-09-10-rapid-dataset-inclusion.md).

The current pool revision protects the three task groups used in the functional-method
assessment and all 30 subsequently exposed open-TSG development task units. It contains
1,962 independent tasks in `research-candidate-pool-v3`; the earlier 1,995- and
1,992-task snapshots remain unchanged. Projecting existing source reviews onto this
pool retains 148 supported task-policy combinations on 67 tasks, without granting
new qualification. The completed 120-assignment development comparison and its
zero-call mechanical replay are [reported separately](experiments/2026-09-11-open-tsg-effects.md);
none of the twelve Holm-adjusted comparisons is significant. This does not activate
the draft protocol or establish selection or mechanism benefits.
The paper-scale planning objective is to use all available independent tasks
that satisfy the prospectively defined scope and candidate-specific design,
after preserving development and qualification roles. It does not freeze a D/C
split, grant missing language/Oracle qualification, or require every task to run
every intervention. Planning and missing coverage are recorded in the
[main-study preparation](experiments/2026-09-11-main-study-preparation.md).

The nine-language syntax path is implemented and tested. The four ordered
source-review cohorts are complete. Preparation makes zero provider calls; local
Codex slots supplied the frozen source-only judgments. All 124 restored inputs
have fresh contract review; 404 current
contracts have complete independent review lineage. The 1,459-task candidate
follow-up uses a frozen book with concrete Python definitions only. Coverage
beyond that book, the other 584 available tasks' candidate reviews, representation,
intervention and independent measurement qualifications remain incomplete.
No formal eligibility follows from source sufficiency. The protocol remains
`SPECIFIED_DRAFT`.

Oracle qualification is scoped to the declared endpoint, languages, task families
and code forms. Qualifying unused profiles or every corpus language is unnecessary.
Use separately labeled secure, insecure and unknown examples plus bounded cases
that address plausible errors in the admitted code forms; retain all errors and
unknowns. Passing those checks supports only that measurement scope, not universal
CWE accuracy. The local qualification command accepts repeated `--profile` values
and records which registered profiles were not qualified. Profile-level gold checks
alone do not certify task-specific coverage. A task can pass source screening yet
remain pending measurement. Functional qualification thresholds are not weakened
to obtain favorable outcomes; partial-contract measurements keep their limits.

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

The final scope, fixed K, model policy, independent task counts, realizations
and request slots require task-level simulation of the actual inference procedure.
`TargetPowerSimulationPlan` freezes the exact `TargetITTPlan`, stratum counts,
ordered positive realization weights, a declared family-support layout, total
four-arm slots, alternative arm probabilities, explicit zero-mixture-mean
realization offsets, unknown/no-code rates, sharing probabilities, replicate
count and simulation seed. Sharing probabilities govern uniform request draws;
they are not claimed to equal arbitrary Bernoulli correlations.

Support can be specified as an exact table of `(coordinate index, task_unit_id,
source stratum, realization index)`. The coordinate order is the sorted model-bound
candidate-record order. The table preserves complete overlap, partial overlap,
disjoint support and higher-order intersections; a scalar overlap fraction is
insufficient. Within a family, a task unit has one source stratum and one realization
per effect. It may have different realizations in different policies. The `shared`
and `disjoint` synthetic layouts remain concise inputs to this same simulation;
they do not qualify arbitrary realized support by themselves.

For each replicate, the simulator allocates one realization, generates actual
categorical no-code/unknown/insecure/secure request outcomes, forms assigned-arm
task-unit contributions, and invokes the same joint max-|T| family analysis used
for results. The independent verifier separately reconstructs the categorical
draws, allocation, outcomes and family analysis. Explicit support uses the frozen
realization for each task-effect coordinate. Shared random components are keyed by
task identity, never by equal row rank in different policies. A digest of every simulated
outcome, per-coordinate meaningful counts, family-status counts, mean standard
error, and mean available critical value accompany each scenario.

Power is the minimum, over family coordinates, of meaningful replicates divided
by all simulation replicates. Non-evaluable replicates count as failures. The
minimum over the frozen scenario grid must meet the declared target; Monte Carlo
uncertainty is reported. The simulation is assumption-conditional planning,
never observed-effect evidence. Its arm probabilities and distributional
assumptions cannot be tuned on target outcomes.

The existing two freeze moments govern planning and final support:

1. Before Discovery outcomes, the qualification and `DiscoveryDesignFreeze` bind
   the planning scenarios, family-size ceiling, task/stratum counts, realization
   weights, allocation and failure rules, all probability assumptions, margins,
   alpha, target power, simulation/analysis seeds and budget. Passing a finite
   planning grid is not a guarantee for every possible selected support layout.
2. After fixed-slot selection and outcome-blind complete-bundle protocolization,
   but before Confirmation outcomes, `bind_target_power_to_assignments` constructs
   the exact table from the replayable assignments. It changes only the filled
   family membership (within its ceiling) and task/realization support. The
   simulator reruns every previously frozen assumption scenario on this table.
   `FormalBudgetPreflight.actual_power_results` retains the full results, and its
   identity is bound by `ConfirmationFreeze`. The independent verifier reconstructs
   the table from assignments and separately replays the simulation and power Gate.

Every nonempty family must pass. An empty family has no fabricated power result.
Failure blocks Confirmation and retains the failed simulation results on the
preflight error; it cannot reduce the target power, change assumptions using
Discovery scores, replace selected slots, top up failed task bundles or discard
failed replicates. Task and stratum counts remain fixed per effect within each
track; unequal per-effect counts are not silently accepted by this repair.
The former Gaussian calculations, including the historical 100-Atomic/170-Pair
suggestion, cannot qualify the design. Previously frozen non-claim packages remain
verifiable under their original shared/disjoint support checks; they cannot gain
formal claim authorization without the actual-support check.

The 10-task reviewer smoke deliberately uses a 0.01 engineering power target to
exercise package plumbing. It is labeled TESTED and makes no scientific power
claim. It neither selects a formal target nor supplies a formal sample size.

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
[`docs/research-dataset-spec.md`](research-dataset-spec.md). Its counts are design targets until
the gates in this section and that document produce a frozen task manifest. In particular, the
older 296-unit layout is a superseded planning example. No formal role counts are frozen.
The final assignment count must derive from qualified hypothesis-specific eligible populations.

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

## 21. Active Artifact and Historical Boundary

The active path uses the existing schema-3 records for role, policy/model, selection,
realization allocation, assignments, outcomes and inference. It is still a draft:
repairs update this one implementation and its specification, without adding a
parallel protocol, wrapper, or migration framework. Task units use `task_unit_id`;
source curation's frozen cluster identifiers retain their original meaning.
Request-randomness slots and nullable provider seeds are distinct fields.

Never overwrite a frozen bundle or reinterpret it under repaired producer bytes.
Historical v1/v2 and earlier development-smoke readers remain available at their
Git revisions, outside active imports and commands. A changed producer or schema
requires a new output location and fresh applicable qualification. Earlier results
can be checked with their matching reader but cannot authorize a current claim.

The target result index is one exact schema-3.0 bundle. It contains the five-role manifest, accepted
RQ1 budget, discovery design freeze, fixed-slot ledger, shared union and dispatch, the frozen target
randomization plan, model-invariant task-policy bundles, canonical assignments, formal budget
preflight, confirmation freeze and study index, shared assigned-arm evidence, fixed-slot Yield result,
formal report authorization or explicit null, resolved execution artifacts or explicit null,
RQ tables, and an independent verification receipt.
Its read-only target verifier must reject missing or extra files, strictly reconstruct every typed
record, and independently replay policy-level protocolization reuse, deterministic complete-block arm
order, variant digests, provider seeds, and all downstream scientific fields rather than trusting the
stored receipt. A claim-bearing package additionally requires the checked-out author decision to authorize
formal execution and the qualification-data manifest to be FROZEN. The verifier resolves actual
execution artifacts, replays generation request/model/arm/task/prompt/seed bindings, raw code, local
Oracle and blinded functional evaluation, and reconstructs every outcome. Three arbitrary digest
references or a relabeled smoke package cannot grant authorization. This consistency check is not
cryptographic proof that a remote service ran. A claim-authorized index does not replace its referenced raw responses,
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
realization specifications, task realization bundles, allocation-specific eligibility, and assignments
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
| RQ1 baselines and `K` can be selected independently | Phase 0 author decision, 2026-08-31 | compare Core, Core+Expert, and Core+Expert+Random worst-case envelopes first; exact baseline set, `K_A`, `K_I`, tasks, realizations, slots, margins, and provider cap remain qualification-blocked |
| prospective calls may mix models or follow a dynamic alias | Author decision, 2026-09-02 | every prospective external LLM role uses Beijing Alibaba Bailian fixed snapshot `qwen3.7-flash-2026-07-15`; dynamic aliases, fallback models, replication models, and hidden retries are forbidden. Each assigned role must still qualify independently, and the historical Max functional-judge result is not transferable |
| a preexperiment budget authorizes formal execution | Author decision, 2026-09-02 | at most CNY 100 is authorized for non-confirmatory preexperiment and role-qualification calls only; it cannot activate the formal protocol, consume a formal evidence role without a role freeze, or promote exploratory outputs. The full formal cap remains unapproved |

| one realization per task but a fully crossed estimator on one common population | inconsistent draft §§9.1 and 11.2–11.3 | prospectively use a fixed-q mixture of realization-specific protocolizable populations; execute one realization per task and preserve failed allocations |
| Gaussian max-T planning treated as full procedure simulation | earlier planning implementation | generate task-level categorical outcomes and run the actual weighted family bootstrap, counting every non-evaluable replicate |

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
with its explicit measurement scope under Section 11.1, complete joint-realization
support, and a supported Oracle Gate under Section 24.7.

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

Pair uses the same §10 `AssignedArmITTRecord` block key and the same §9.1
one-realization allocation and exclusion rules. The policy/protocol records bind
the Pair context, two factors and joint realization; no second randomizer or
factorial block schema is active. Each block contains equally many assignments
to `A00`, `A10`, `A01`, and `A11`; its total slot count is a positive multiple of
four. All descendants of one task unit remain together during bootstrap.

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
four cells, reproducible endpoint decisions, preserved `unknown`, and a separately
labeled bounded gold calibration covering representative admitted code idioms and
plausible differential measurement errors. A policy-only endpoint need not expose
an internal mechanism trace. `UNSUPPORTED` pairs do
not enter randomization. There is no pair-specific Oracle and no partial-support status.

`interaction_claim_scope` is exactly `policy_only` or `mechanism_eligible` and is also frozen before
randomization. `policy_only` permits a claim only about the joint Prompt-policy response surface.
`mechanism_eligible` additionally requires authenticated mechanism evidence, that the Oracle endpoint is not mechanically defined as
the conjunction of the two factors and that independent evidence can distinguish both controls.
Statistical significance cannot promote `policy_only` to a mechanism-synergy claim.

The assignment-level Oracle result remains `secure`, `insecure`, or `unknown`. The Gate status is
not an assignment outcome, and factor realization is not substituted for the security label. A
profile that defines full security as the logical conjunction of both controls may identify a joint
Prompt-policy interaction, but that result cannot be promoted to universal mechanism synergy without
an outcome-induced-interaction audit and independent endpoints for the two factors.

### 24.8 Estimands, unknown bounds, and functionality

For model `m`, let `mu_z1z2` be the Section 11 weighted task-unit mean under cell `(z_1,z_2)`,
under the realization-specific population mixture in §11.2. Report:

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

The following functionality non-inferiority analysis is specified but inactive;
its secondary simultaneous family and independent implementation are not yet frozen.
Once activated prospectively, functionality receives its own factorial estimates.
A security-interaction claim cannot receive a
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
antagonism. Future paper-facing response surfaces may use neutral labels such as `positive_nonadditive_pattern`,
`negative_nonadditive_pattern`, `conditional_activation_pattern`, and
`simple_effect_sign_reversal`, but the current classifier is blocked under §25.5.
The following label requirements cannot activate it without frozen predicates.
A named **security policy interaction** requires a simultaneous
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

### 25.1 D0: context-only Discovery-population preparation

D0 can occur only after representation qualification and freeze, before the Discovery population
is frozen or any Discovery outcome/selector feedback is read. It is optional data preparation,
not an extra scientific stage. It cannot recur during prioritization, hypothesis freeze,
Confirmation preparation or reporting, even if its original budget was not exhausted.

Before the census, fix context predicates `C_k`, independent task-unit targets `m_k`, permitted
natural sources and metadata, acquisition/review budgets, source order or independent seed, and
stopping rule. Contexts describe inputs, operations and non-target task boundaries and must remain
invariant under the studied feature ADD/REMOVE. Requirement-to-target relation support cannot be
renamed as context coverage. Count each deduplicated task once per context; a task may occupy
multiple contexts, but its operation instances do not increase the independent sample size.
Unresolved context membership is reported separately and never recoded as absence.

The trigger, allocation and stopping calculation is only
`n_k = count(task units with C_k = PRESENT)` and `d_k = max(0, m_k - n_k)`.
`CoverageTargetProfile` schema 4 contains context targets, representation identity, sources and
budgets. Neither it nor the D0 census/request carries feature states, Pair cells, candidate slots
or fold support. The same context counts must produce the same deficits and acquisition requests
when features, Pair support, FCI/RD or outcomes change. `STATE_TARGETED` is not an active mode;
earlier frozen records retain their old interpretation in their archived implementation.

The four retained records are the pre-census, prospectively fixed plan, natural-source/deduplication
receipt and post-census. One round ends when all context targets are met, a frozen acquisition or
review budget is exhausted, or the preset sources are exhausted. Remaining context gaps are
reported as `COVERAGE_GAPS_RETAINED`; they do not by themselves veto already covered candidates.
Natural variation, four-cell support, lineage overlap, candidate capacity and power are separate
Discovery/design Gates. A context count is no guarantee of any of these.

Only independently sourced natural tasks are permitted. Paraphrases, interventions, synthetic
cell completion and duplicate descendants are forbidden. Existing role bindings remain exact;
new accepted task units may enter only Discovery and must be disjoint from development,
qualification and reserved Confirmation tasks and their near-duplicate groups. Outcome- or
selector-guided source selection, a second round and supplementation after Discovery starts are
prohibited. D0 does not reallocate or replenish Confirmation.

The plan explicitly discloses its change to context and source composition. Outcome blindness is
an input restriction on acquisition, `A = pi(C, allowed_metadata; seed)`, not a theorem of statistical
independence from potential outcomes. Report per-context counts before/after, unique new tasks,
sources, retrieval/review effort, unknown memberships and remaining gaps. All selector variants
use the same accepted pool. No D0 acquisition is executed until representation and these targets
are prospectively qualified and frozen.

### 25.2 D1: population-version binding

`DiscoveryDesignFreeze` binds the accepted pre/post census lineage, qualification identity,
`CoverageTargetProfile`, supplementation decision (`NOT_REQUESTED`, `PLANNED`, or `COMPLETED`),
permitted data roles, and the exact Discovery population manifest. Candidate universes, folds, FCI,
RD, and selector ranks must all point to that same population identity. A changed member, role,
representation digest, target profile, or census invalidates downstream discovery artifacts rather
than silently regenerating them under the same freeze.

For a supplemented population, the pre-census references immutable role manifest
`M0` and the post-census references immutable `M1`. The existing D0 receipt embeds
`pre_data_role_manifest=M0` and binds `M1` with `data_role_manifest_sha256`; the
ordinary study package stores `M1`. `M1` must retain every existing binding exactly,
including all task records, source digests, roles, near-duplicate groups and exposure
histories. New tasks occupy new `DISCOVERY` bindings only. Their exact set must
match the receipt, their provenance/exposure must match its accepted dispositions,
and their near-duplicate groups must be distinct from each other and every old
role. Each accepted disposition identifies a source family within the prospectively
qualified coverage profile. The profile, catalog and representation qualification
identities are identical before and after D0. Outside that qualification scope,
the extension is blocked rather than inheriting an acceptance result.

The qualification bundle, its original plan and power/budget memo continue to bind
`M0`. The Discovery freeze binds `M1` only after production and independent checks
prove this exact additive relationship. No original binding is rewritten and no
qualification result is rebound to `M1`. Without supplementation `M0=M1`; this
exception permits neither a second round nor changes after Discovery has frozen.

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

The current implementation retains only an inactive plan with explicit
`BLOCKED_NO_FROZEN_CONTEXT_RULE` status. Its serialized modifier tuple is empty and its rule
digests are absent, preserving the interpretation of existing tested packages. It does not expose
a configurable future modifier specification or accept a `FROZEN` plan. The exact modifier levels,
joint bootstrap rule, multiplicity family, and support thresholds must be prospectively frozen
before an active implementation can produce intervals, inferential statuses, tables, or claims.

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
The current runtime rejects classified labels and active plans; the retained serialized label
and precedence tuples are empty and the predicate digest is absent.

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
