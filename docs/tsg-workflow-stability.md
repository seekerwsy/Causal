# Current TSG construction and development evaluation

The normative protocol remains [SPECIFIED_DRAFT](protocol.md). This construction
path implements representation; it does not activate formal experiments or certify
semantic accuracy. TSG relations represent task meaning, not causal edges.

## One model interface and one compiler

```text
actual system/user input and language
  -> complete source records
  -> structural checks and direct preview compilation
  -> one source review
  -> at most one complete-record revision, followed by direct compilation
  -> save source contract + graph
  -> separate candidate applicability/expression assessment
  -> save candidate-state table, project a read-only assessed graph
```

`source_records.attempt_graph` is the extraction entry point. On a malformed
initial response it permits one mechanical correction in the same schema. The
semantic review checks both declared bindings and missing source meanings. If it
finds a problem, the model returns the complete revised records in that same
schema, using the original source and review. There is no partial-patch schema,
editable-region expansion, rejected-claim matcher or patch merger. Extraction,
review, revision and deterministic readback share `record_semantics`.

The compiler maps records directly to an `OpenTaskContract` and the canonical
TSG. The retired token-inventory model response and generic graph-response
recovery adapter are gone. No alias merging or silent fact/edge removal repairs
model outputs. Source quotes are located directly as quotation/occurrence pairs;
there is no quote-to-token-index-to-quote conversion or token-index request.
Lexical boundaries only delimit source units and validate quoted spans.

The trace saves requests, response schemas, raw responses, pre-review records and
graph, review, and revised records. Structural success is explicitly distinct from
semantic success. A full revision can still omit or change a supported meaning;
the compiler cannot certify that it repaired the review findings. Independent
source-reference evaluation must measure that risk. No live-model improvement
is claimed by this refactor.

## Shared candidate and visualization projection

The saved source contract owns facts, bindings, conditions and scope. Graphs are
its deterministic projections. Source-contract schema 4 has no `feature_states`
field. `factor-states.json` stores each task's `source_contract_id`, assessed
`states` and unresolved notes; `assessed_graph` checks the source identity and
compiles the same graph with those states for downstream use. No second source
contract is created. `prompt_tsg.source_nodes` supplies the same local-ID
to graph-node transformation to construction, scope assessment, candidates and the
viewer; none of these readers rematches nodes by concept text or evidence span.
Graph validation retains schema, identity, endpoint and composition checks in one
place instead of repeating them while building nodes.

When a viewer case contains both a contract and a saved graph, the viewer derives
the graph from the contract and checks the saved projection agrees. A disagreement
is reported rather than displayed as a different interpretation. Graph-only
artifacts remain inspectable after source/catalog validation, without invented
relation citations. Node/edge evidence, generation-layer display, graph comparison,
SVG export, prompt comparison and saved-result inspection remain available.
The viewer overlays the separately saved states after checking the source graph.

`extract_task_contract` only constructs source semantics. The batch extraction
command subsequently calls `assess_candidate_scopes`; this function can also
consume an existing source attempt with its matching frozen catalog. A failed
assessment is recorded separately and does not mark successful source extraction
as failed. Missing judgments remain unknown. Independent qualification replays
both outputs and still checks semantic completeness. It is never invoked by
the extraction module; the CLI prepares a prospective reference before calls.

## Preserved meaning

- Objects and operations have explicit identities. Participant roles, execution
  guards, contextual conditions and ordering belong in structural fields; prose
  cannot fill an empty field.
- A requirement retains its full content, direct targets, conditions and scope.
  Several direct targets each receive the complete predicate. Workflow participation
  does not make every operation a requirement target.
- Task-wide and quantified `each` requirements remain at their declared boundaries;
  they are not broadcast to observed operations or reduced to an incomplete list.
- AND/OR/NOT/opaque structures remain available. Shared guards are inherited;
  alternative or negated members do not become independent Atomic requirements.
- Owned ordering relations remain arguments of their requirement. They are not
  promoted to unconditional execution order when that requirement is removed.
- Generation and runtime remain distinct layers. Imports provide dependency context,
  not proof of runtime use; explicit library requirements and output formatting bind
  their source-supported artifacts. Implementation scope is only a fallback.
- Unknown force, coverage, expression or applicability stays unknown. Missing graph
  edges do not establish absence. Candidate assessment sees the original source and
  relevant unresolved information; unrelated uncertainty is not an automatic task veto.

Open development derives concept identities from full definitions and node types.
Frozen vocabularies cannot expand or change meaning. Candidate construction selects
complete existing bindings and equivalent concepts; it does not split source nodes
or repair their semantics. The active method remains Atomic-only.

## What the program checks

Checks cover field types, unique IDs, valid references, declared relation signatures,
source coordinates, and composition/scope consistency. Invalid or dangling references
are rejected. Overlapping source evidence is allowed; exact duplicate graph facts
remain invalid. Program checks do not infer source entailment, applicability from
role/domain tables, or a missing participant from its name.

Source coverage and dependency information remain visible to review and assessment.
Deterministic dependency propagation records what declared structure reaches; it is
not proof that the structure contains all relevant dependencies. No semantic state
is inferred merely because compilation succeeded.

## Verification and historical evidence

The default reviewer suite exercises conditions, scope, composition, owned order,
source identity, unknown handling, complete revision, candidate construction and
independent semantic evaluation. Its end-to-end smoke also covers the seven-stage
workflow and independent result replay with offline responses. It is not an estimate
of automatic extraction quality; API experiments require a separately declared scope.

The implementation before this simplification is preserved on
`codex/pre-tsg-linear-refactor-20260925` at `2d397e6fa`. Earlier experiment descriptions
and results retain their original interpretation in [experiments](experiments/).
Old frozen traces must use their captured implementation and request schemas;
the current package does not maintain a second compatibility extraction path.
