# TSG requirements to candidate hypotheses

This is the active candidate-construction path inside representation and
prioritization. It replaces predesignated development policies as the source of
new study candidates. Existing frozen development plans retain their original
meaning. The protocol remains `SPECIFIED_DRAFT`; no formal Discovery is activated.

The chain is:

```text
source records: requirements include composition, guards and target scope
  -> exposed development source graphs
  -> source-only LLM selection and normalization of equivalent atoms
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

The model inventories every requirement node as `included`, `not_actionable` or
`unresolved`, with a reason. For each proposed factor it supplies a definition,
atomicity rationale and source occurrences. An occurrence names existing
requirement nodes and an exact operation/input/condition scope. Each source
requirement used by a factor must already be an asserted atomic obligation.
Construction records reliable atoms and finite composition, including shared guards.
Atomicity alone does not establish independent editability. Source citations may overlap. Conditions, negations,
quantifiers and thresholds must retain their full meaning, rather than being
split into disconnected words. Multiple equivalent nodes can support one factor.
The model cannot supply policy keys, review acceptance, scores or effect direction.

Source statement modality is retained: input assumptions and unresolved normative
force are not eligible editable requirements, even when represented as constraint
nodes. The constructor enforces this distinction, rather than relying on the
proposal model to exclude them.

A correctly declared composite is retained with `not_actionable` or `unresolved`
and a reason. The constructor follows conjunction only to already declared atoms;
alternative and compound-negation members are not independent obligations. A wrongly
declared atom requires source repair, never downstream splitting. One source node cannot be reused
under different normalized requirement definitions. The same atomic meaning may
still have multiple exact source scopes; those can produce different scoped factors.

The compiler verifies requirement-to-operation and requirement-to-subject edges,
input use, exact conditions and complete dispositions. It constructs stable
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
confirm that every supporting source node already expresses one atomic requirement;
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

Scope selection uses only operation concepts, input-use edges, subject concepts
and source-supported execution guards or non-gating `context_for` conditions. The
selector records which conditions actually gate execution. There must be one exact structural match; multiple
matches or missing structure return `null`, without choosing whichever scope has
a convenient feature state. Requirement-only guards need independent source context
before automatic binding. Otherwise the candidate remains unresolved while its
source representation can still be correct; the compiler never turns that guard
into an operation execution condition for convenience.

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

The candidate tests cover atomic source nodes, rejection of downstream splitting,
equivalent occurrence grouping, the same atomic meaning at distinct scopes,
source-only inputs, source/condition grounding, review boundaries, both operators,
a complete file path into positivity, old-catalogue
rejection, missing graphs, ambiguous bindings, empty universes and retained model
failures. All responses are synthetic fixtures; they test implementation behavior
without asserting model accuracy or natural candidate support.

`data/method/tsg-candidate-construction-development-v1/request` retains the predecessor zero-call
request prepared from the already exposed seven-case v10 scope check. Six source
graphs replayed and the seventh failed graph remains listed. Its original defects
are not repaired or counted as qualification. Its earlier downstream-splitting
instructions are not the active method. Current requests declare
`requirement_granularity=atomic_source_requirement`; prepare a new request in a new
directory to use the revised rule. Request preparation does not certify source
atomicity. No natural model proposal, semantic
acceptance, protected-task exposure or effect experiment was executed in this change.

Before the atomic-source correction, the 2026-09-12 clean Python 3.12.13 verification passed all 311 selected reviewer
tests (113 outside that selection), including the 17 candidate-construction tests.
The seven-stage reviewer smoke and independent result verifier also passed,
retaining all 80 simulated assignments. The exact environment, commands, input
identities, implementation hashes and output locations are recorded in
[`validation/report.json`](../data/method/tsg-candidate-construction-development-v1/validation/report.json).
These results establish implementation behavior only, with zero provider calls.

The atomic-source correction passed 315 selected reviewer tests (113 deselected)
in the same clean Python 3.12.13 environment. The focused source-inventory and
candidate checks passed all 31 cases, including two atomic requirements from one
source clause, rejection of downstream splitting and preservation of the same
atomic meaning across distinct operation scopes. The prior smoke package was
independently reverified without changes. Exact commands and identities are in
[`validation-atomic-source/report.json`](../data/method/tsg-candidate-construction-development-v1/validation-atomic-source/report.json).
No real provider calls or new natural-task exposure occurred. Source atomicity
remains a semantic review obligation; these fixture results do not qualify an LLM.

The subsequent [program-ID/local-availability revision](experiments/2026-09-12-atomic-local-representation.md)
removes first-response self-references and adds explicit source-impact decisions
before fixed-scope assessment. It passed 320 reviewer tests and a six-case authored
reference replay. The authorized real check is now closed: 13 calls produced six
first inventories, three binding rejections and zero fully accepted cases. Only
one of 20 reference scopes received a state answer; 19 remain unassessed. Candidate
selection still cannot split source nodes, repair missing bindings or turn source
impact declarations into independent qualification.

The current [single-role revision](experiments/2026-09-12-single-role-representation.md)
derives input/output incidence from one source-cited role declaration. Its new development
reference retains all 20 expected scopes, explicitly allows four shorter equivalent anchors,
and requires the return operation and selected-row binding without demanding an additional
synonymous requirement node. Previous references and verdicts remain unchanged. Candidate
selection still cannot repair missing or misclassified source atoms.
The real six-case check is closed at 11 calls, zero full acceptance and 19 unassessed
reference scopes. Role/incidence consistency holds, but source inventory omissions,
semantic substitutions and corrections confined to prose remain. These results do
not authorize natural candidate selection or another unbounded extraction iteration.

## Existing-material feasibility after the atomic-source correction

The 2026-09-12 local audit asks what the already exposed material can establish
before another extraction run or a selector comparison. It reuses saved source
reviews and inspects the predecessor candidate request; it does not assign new
feature states, alter old verdicts or qualify old graphs under the new rule.
The current implementation and test file hashes match the five hashes in
`validation-atomic-source/report.json`. The saved 315-test result is therefore
reused for those unchanged files; this audit did not rerun that suite.

| Existing material | Observed evidence | Permitted use and remaining gap |
| --- | --- | --- |
| Thirty exposed natural task units in `open-tsg-effect-development-v1` | The selection record says “Previously source-supported ADD candidates”; fixed hash order was applied within 12 SQL, 10 command and 8 path selections. No outcomes or selector ranks were used. | Source and representation development. This selected sample cannot estimate natural two-state or Pair four-cell prevalence in the research population. Outcome blindness does not remove prior ADD-candidate selection. |
| Original source review of those thirty units | Twelve ADD designs were supported under the old rules: 3 SQL, 8 command and 1 path. Six path requirements were already present; one command requirement was expressed or partial; ten operation contexts were unresolved; one task had a different endpoint. | Preserve all thirty identities and original judgments. These counts are historical source-review dispositions, not states of the new graph-derived factors, qualified support or evidence that the remaining eighteen sources are unusable. |
| Three SQL source-reviewed reference graphs | The saved report explicitly records source review, zero provider calls and no automatic-extraction qualification. | Reference material for a new bounded source review. Check exact prepared inputs and atomic meanings before reuse; do not present these graphs as current automatic extraction or natural candidate discovery. |
| Predecessor seven-case candidate request | Six graphs: two natural and four synthetic; one natural graph missing. Of 29 emitted requirement-type nodes, four are safety-requirement nodes, all in synthetic cases. | Inspect source defects and candidate plumbing. The emitted-node count does not establish completeness or absence of security requirements in the natural sources. Synthetic requirements cannot supply natural candidate/support evidence. The request lacks the current atomic-source declaration and remains archival. |
| Closed three-case source-role check | Three actual first-inventory calls produced zero compiled graphs after invalid coverage references; raw-source review also found semantic omissions and substitutions. | Diagnose the exact first-response interface and semantic errors. This precedes the atomic-source correction and supplies neither a result for the corrected extractor nor downstream relation/scope evidence. |

The predecessor request contains a concrete granularity defect in
`synthetic.condition_and_prohibition`: node
`tsg_node_a09ca5d3eb006cd2bf01df53838107a09b4bf6a1853746c8f0cf3f330dceb479`
uses `feature.forbid_parameterization` to combine prohibiting parameter binding
with requiring SQL construction by concatenation. Under the current rule, this
needs separate source requirements with their original raw-mode condition and
operation/input bindings preserved. It must remain unresolved in a candidate
proposal made from that old graph. This observation does not modify the old
graph, catalogue, scope judgments or acceptance result.

The next development decision is consequently bounded: establish source-reviewed
atomic meanings and their operation/input/condition bindings on the already
exposed small reference set before producing a new candidate request. A
source-authored reference can check the downstream implementation, but must stay
distinct from a real model extraction. The first-response coverage-ID failure
also remains unresolved by the atomicity instruction; repairing that interface
and checking semantic fidelity are separate requirements for a future real run.
Conditions or thresholds cannot disappear merely to make a scope bindable.

No natural Full/RD-only or Full/No-Relation comparison can yet be reported from
these materials under the current candidate path. The missing evidence is an
accepted source-derived candidate set, extraction and qualification bound to its
catalogue, and same-population natural support/folds. Existing synthetic smoke
can exercise the computation, but cannot establish selector benefit or Yield@K.
Neither this gap nor the thirty-task counts authorize state-guided acquisition,
synthetic cell filling, lower support thresholds or replacement of failed cases.

Audit sources: the original
[`selection.json`](../data/method/open-tsg-effect-development-v1/exposure/selection.json),
[`reviews.json`](../data/method/open-tsg-effect-development-v1/source-review/reviews.json),
[`SQL reference report`](../data/method/open-tsg-sql-refinement-v1/reviewed-representation/report.json),
[`predecessor request`](../data/method/tsg-candidate-construction-development-v1/request/request.json),
and [`closed three-case summary`](../data/method/open-tsg-scope-development-v1/source-role-check/analysis/summary.json).
The audit made zero provider calls and exposed no new natural task units. It
added this reading of existing material only, with no new empirical or formal
qualification result.
