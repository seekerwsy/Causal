# TSG requirements to candidate hypotheses

This is the active candidate-construction path inside representation and
prioritization. It replaces predesignated development policies as the source of
new study candidates. Existing frozen development plans retain their original
meaning. The protocol remains `SPECIFIED_DRAFT`; no formal Discovery is activated.

The chain is:

```text
source records: requirements include composition, guards and target scope
  -> exposed development source graphs
  -> source-only selection and normalization of complete single requirements
  -> semantic review of the generated factors
  -> existing concept freeze, generated Atomic policy records
  -> fresh extraction using that catalogue
  -> automatic, state-blind task-scope binding
  -> existing qualification positivity, folds and prioritization
```

Uncommitted atomic source records can be locally patched during construction; the
program then compiles their graph bindings. This does not authorize the candidate stage to change source
nodes. The [current TSG workflow](tsg-workflow-stability.md) specifies the bounded
review/repair policy and its development evidence. Historical repair comparisons
retain their original outcomes.

A structural `atom` is neither sufficient nor universally necessary for eligibility.
Existing factor review must justify the one changed requirement and
the non-target meanings retained. Whole-task and explicitly universal requirements
are preserved in `retained_requirement_scopes`; no finite local instance list is
invented from them. They may be whole policies at their task/function boundary;
they do not imply a local instance policy or a local absence judgment.
All editing reads the complete effective system/user input, including unresolved
requirements. A requirement still expressed by the system cannot become absent by
deleting its user repetition. Generic template wording is not automatically
equivalent to a specific policy. Source definition reuse does not certify new binds.

Graph construction now returns an inspectable source graph before any candidate
state call. `_assess_candidate_scopes` consumes that graph, applies the frozen
candidate domains and judges applicability/expression. It cannot add, split or
rebind source facts. Its failure preserves the graph and leaves candidate states
unknown. This separation changes responsibilities and artifacts, not the meaning
of existing scope judgments or the seven scientific stages.

## What the model proposes

`candidate_construction.candidate_request` reads the prepared source prompts and
their recorded development contracts. It replays the exact graphs and exports
nodes, meanings, source quotations and edges. Outcome values, feature-state
assessments, CWE/task-family routing labels, support, ranks and preselected
intervention names are not model inputs. Missing graphs remain listed.

`candidate_model_request` gives each source node one short, task-qualified reference.
Every requirement carries its definition, source quotation and program-derived
`complete_bindings` together. The response schema requires exactly one decision
under that same requirement reference: `include`, `not_actionable` or `unresolved`,
with a rationale. An included unit supplies only its normalized label and complete
definition. Other decisions leave those two fields empty. There is no second binding
index, separate exclusion inventory, or model-selected basket of source nodes.

The program restores all complete boundary/input/condition bindings of each included
requirement; the model cannot invent, choose or rewrite those coordinates. A unit
without a complete binding cannot be included. Task-wide policies retain the task
root; universal policies retain their original task/function boundary and target
class, never a hand-picked instance. Conditions, negations, quantifiers and thresholds
remain part of the complete requirement. Separately judged equivalent units can
deduplicate under the existing normalized-definition and exact-scope rules. The model
cannot supply policy keys, review acceptance, scores or effect direction.

A requirement that directly constrains only source objects retains that exact
object set as an `objects` scope. The task root is its coordinate anchor, not a
task-wide constraint. No using operation or producing operation is invented, and
sharing an object across operations does not duplicate its policy. An explicit
operation-plus-object requirement remains a different binding. A missing or
ambiguous object identity leaves the scope unresolved.

These are identity and binding-preservation guarantees, not semantic eligibility
guarantees. A correctly copied binding can still be wrong in the source graph; a
faithful definition can still describe ordinary required functionality, a duplicated
policy that cannot be independently removed, or more than one editable requirement.
The model must judge those meanings against the full source, and explicit semantic
review remains necessary. Neither an `atom` label nor a supplied binding certifies
security relevance or independent editability. Source citations may overlap.

Source statement modality is retained: input assumptions and unresolved normative
force are not eligible editable requirements, even when represented as constraint
nodes. The constructor enforces this distinction, rather than relying on the
proposal model to exclude them.

A conjunction parent remains an organizer of separate requirements. A whole OR/NOT
expression can be considered only when its members share one exact binding and a
review confirms one choice/prohibition policy. Opaque expressions and compounds
with differing member bindings remain unresolved, not forced into a simple leaf.
Alternative and compound-negation members are not independent obligations. A wrongly
declared atom requires source repair, never downstream splitting. One source node cannot be reused
under different normalized requirement definitions. The same atomic meaning may
still have multiple exact source scopes; those can produce different scoped factors.

The compiler verifies direct edges or retained boundary/class, input use where
the source actually binds an operation, exact object sets for object policies, complete
conditions and exactly one decision per source requirement. It constructs stable
feature IDs from the semantic definition, requirement role and structural scope
selector. Identical definitions and scope signatures deduplicate; distinct scopes
remain distinct factors. Source context concepts merge only when their type and
definition are identical. Broader semantic generalization is not inferred from
similar names. The program's fixed baseline-template concepts retain their exact
IDs and definitions so the new catalogue can enter the actual extractor.

These checks establish structural grounding and consistent source mappings, not
the truth of semantic atomicity or equivalence. `PENDING_SEMANTIC_REVIEW` produces no frozen catalogue or usable
policies. A review must bind the exact request and response and cover every
generated factor, explicitly assessing source support, atomicity, normalization,
context independence and preservation of task scope. `single_requirement` must
confirm one independently editable requirement, including its conditions and scope;
`normalization_valid` must confirm that the proposed definition preserves that
whole meaning. A one-node/one-definition mapping alone cannot detect selecting
only half of a composite requirement. Review can accept, reject or
leave unresolved; it cannot introduce a new factor or silently edit a proposal.
All exclusions and unknowns remain in the proposal.

## From reviewed factors to the existing method

Main now generates Atomic policies only. Pair design and compatibility review
remain on `codex/pair-interaction-research`; old Pair bundles are not main inputs.

The accepted definitions enter `prompt_contract.freeze_open_concepts`; source
concepts and derived factor concepts retain separate provenance. The programme
generates both ADD and REMOVE `AtomicPolicyKey` records for each accepted factor.
Development exemplars can all express the requirement: the builder does not claim
that any other task lacks it or that either operation has natural support.

New requests declare `requirement_granularity=complete_single_requirement`.
Prepare a fresh request rather than changing the interpretation of a frozen one.
The catalogue stores `feature_scope_selectors`: boundary kind, quantified class,
expression kind, internal policy conditions and independent execution context.
Order requirements additionally freeze `policy_relations` with exact direction and
operation operands. These relations belong to the requirement; operands are not
extra direct targets. Scope selection requires unique independent endpoints,
not an already expressed order. Positive evidence must match the complete relation
envelope. Different OR/NOT member envelopes remain represented but unprojected.
Scope selection reads only task/operation identity, input-use bindings and execution
conditions, or the exact source-object identities for an object policy. It never
reads the requirement or its state; ambiguity returns `null`.
Requirement-only guards remain part of the policy without becoming execution edges
or additional task-selection prerequisites. They may disappear when that policy is
removed. Positive expression requires their exact structural binding; a correct
description cannot replace a missing guard. Applicability still requires source
support for a meaningful, feasible comparison, not merely a root or an empty class.

Fixed-scope assessment uses the same selector as binding. Its result remains one
state per complete scoped policy; a binary variable does not erase the scope held
in its identity. No extra covariates, FCI variables or interaction analysis are
automatically introduced. A root-bound policy reads the whole effective input.
Independent source review includes retained scope assertions. Reviewed edits check
non-target composition and whole/universal scopes as well as ordinary edges.
They also preserve each non-target owner's relations, even when another owner
names the same pair. Removing a target may remove its own relations, while
independently supported ordinary order and other owners' relations must survive.
Only expression members and exclusively used guards inside the target citation can
belong to its edit; shared context, operation and object evidence remains protected.
Projecting an object requirement does not certify editability. A size requirement
whose citation also contains an input type cannot be removed by deleting that
whole citation. An object mentioned only inside the target requirement may lose
its scope anchor after deletion. Existing overlap protection and reviewed rewrite
checks still apply. Unresolved source-impact metadata that cannot establish
object-level relevance remains unresolved, even if no operation-use edge exists.

After the vocabulary changes, extraction must run again under that exact frozen
catalogue. Old graphs cannot be relabelled or have old unknowns converted into
absences. The resulting `scopes.json` contains the existing policies,
`factor_definitions` and complete `task_bindings`. Positivity replays generated
scope geometry and candidate provenance, then independently checks qualification,
source states, coverage and support. Empty reviewed universes remain empty.
Synthetic manually authored scope fixtures are retained to test those downstream
boundaries; they are not a substitute candidate-discovery path for a new study.

## Commands

Prepare a request from an already exposed extraction. `TASKS` must be its exported
prepared tasks, not newly rewritten inputs. `--input-catalog` supplies the original
extractor input catalogue when it is not the generic open catalogue or the exact
embedded frozen catalogue.

```text
prompt-mechanism-study representation candidate-request TASKS EXTRACTION REQUEST --input-catalog ORIGINAL_CATALOG
prompt-mechanism-study representation build-candidates REQUEST DESIGN DRAFT --response RETAINED_MODEL_RESPONSE
prompt-mechanism-study representation build-candidates REQUEST DESIGN REVIEWED --response RETAINED_MODEL_RESPONSE --review SOURCE_REVIEW
```

`DRAFT/review-template.json` contains unfilled review fields, never preaccepted
assertions. Reuse the exact saved response during review; do not resample proposals
until favorable candidates appear. An authorized development run can replace
`--response` with `--evaluator` for one source-only proposal call. It uses the
existing provider client, fixed current model/region, explicit input/output limits
and no retries. Invoking offline commands makes no provider calls. This addition
does not qualify or assign a formal LLM role or grant a provider budget.

`DESIGN` contains only the frozen research scope and downstream settings, not
candidate names or handpicked requirements:

```json
{
  "outcome_id": "oracle_evaluable_secure_code_yield",
  "language_scope": ["python"],
  "api_scope": ["database"],
  "task_archetype_scope": ["query"],
  "operations": ["add", "remove"],
  "model_id": "FROZEN_MODEL_ID",
  "covariate_names": [],
  "support_rule": {
    "minimum_state_task_units": 2,
    "minimum_shared_lineages": 1,
    "maximum_unresolved_fraction": 0.2,
    "minimum_feature_reliability": 0.8
  }
}
```

The numbers above illustrate the input shape only; they are not qualified study
thresholds. The response format and exact model instructions are saved in the
request bundle. The test fixture in `tests/test_candidate_construction.py` provides
complete synthetic source, response and review examples.

After independent representation qualification and fresh extraction with
`REVIEWED/catalog.json`, bind source scopes and run the existing support producer:

```text
prompt-mechanism-study representation bind-candidates REVIEWED FRESH_TASKS BINDINGS --prompt-tsg-bundle FRESH_EXTRACTION --qualification-bundle QUALIFICATION
prompt-mechanism-study qualification positivity FRESH_TASKS REVIEWED/catalog.json SUPPORT --prompt-tsg-bundle FRESH_EXTRACTION --scope-bindings BINDINGS/scopes.json
```

Missing representation qualification produces blocked support; it is never
fabricated by the builder. No edit wording, neutral
counterpart, Oracle support or confirmation assignment is inferred here: those
remain the existing protocolization and measurement responsibilities.

## Development verification

The active authored checks live in `tests/test_candidate_construction.py` and the
existing source-inventory tests. They distinguish task/each/direct scope,
policy-internal versus execution conditions, asserted whole alternatives versus
unasserted members, and preserved versus changed non-target meanings. One complete
policy test covers candidate construction, exact state assessment, both edit
operators and independently authored post-edit graphs. Before/after predicates
remain different factor definitions; the program does not prove open-text equivalence.

Run `python -m pytest tests/test_candidate_construction.py -q` for the local path.
The [2026-09-17 report](experiments/2026-09-17-complete-policy-projection.md) records
this bounded check, the unchanged automatic API-probe failures and its limits.
All these cases are exposed development or synthetic controls, not natural
Discovery/Confirmation support. Earlier counts, qualification rules and outcomes
remain in their original reports and Git history; they are not regraded here.

The subsequent [natural-task check](experiments/2026-09-17-complete-policy-natural.md)
completed two automatic graphs but its single proposal response truncated. Partial
item diagnostics exposed unsupported scope changes and ordinary functionality
proposed as factors. No candidate catalogue or actual edit was accepted; the
expanded structural capability has not yet demonstrated a natural candidate gain.
