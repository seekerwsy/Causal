# Current TSG construction and development evaluation

The active research protocol remains [SPECIFIED_DRAFT](protocol.md). The seven
scientific stages remain representation, prioritization, hypothesis freeze,
intervention/randomization, measurement, outcome assembly and inference/reporting.
This document describes development within representation, not formal qualification.

## One active construction path

```text
actual system/user input
  -> source records with participants, requirement composition, guards and scope
  -> one ordinary source review and at most one local patch
  -> deterministic TSG compilation
  -> separate candidate applicability/expression assessment
```

The model no longer receives a separate free binding task. Ordinary extraction and
`scripts/run_tsg_development.py` both enter `_attempt_source_graph`, which uses
`source_records.attempt_graph`. Old request/binding helpers serve record compilation
and retained fixtures; frozen old runs reproduce with their own execution archives.
They are not an alternative active workflow.

1. **Prepare exact input.** `task_input.py` combines actual system/user messages and
   declared language. The program indexes source units; users do not manually number
   files. Generation must use the corresponding input. Recognized fixed system
   requirements are compiled once.
2. **Extract complete records.** Objects are declared once. Operations contain their
   required participants, roles, results and explicit execution guards. Each atomic
   requirement contains its complete predicate, modality, targets and conditions.
   Composite records preserve and/or/compound-not/opaque member structure. Only
   asserted atomic obligations can support independent factors; conjunction carries
   its shared guards to members, while alternative/negated members stay non-independent.
   Requirements preserve thresholds, negations, exact result formats and variable names.
   In open development, the program assigns new concept identities from exact full
   definitions and node types; provisional model labels cannot merge different atoms.
   Exact unique known meanings retain their supplied IDs. Frozen concepts are unchanged.
   `scope_kind=task` applies a runtime requirement to all runtime operations;
   `implementation` binds generation requirements; `targets` names exact local targets.
   A nested requirement guard produces only condition-to-requirement edges. It cannot
   also gate an operation unless the model separately asserts an execution condition.
   Source-supported `scope_conditions` instead produce non-gating `context_for` edges;
   independent context cannot be inferred merely from a target requirement's guard.
3. **Distinguish modality.** `obligation` prescribes behavior. `assumption` records an
   expected input or premise as a neutral constraint, without prescribing validation
   or rejection. `unresolved` preserves ambiguous force and blocks affected assessment.
   Contract `source_inventory.statement_kinds` retains the distinction. Candidate
   construction rejects assumptions/unresolved statements as editable requirements;
   positive feature-expression evidence requires an obligation. Absence of a source
   requirement never means absence of protection in generated code.
4. **Check and repair once.** Mechanical validation checks schema, citations,
   references, layers and legal scope, with at most one mechanical replacement.
   One model review checks every record and every source unit. It identifies precise
   rejected fields/list items and omissions. Review and patch receive the same role
   definitions and exact scope/guard interpretation used during extraction/compilation.
   The program first decodes actual bindings with `structural_readback`. Guards and
   targets come exclusively from their fields, with empty guards shown as unconditional.
   Correct definition text cannot supply missing structure. Readback is retained in
   the attempt trace for debugging. Detailed binding judgments and source-to-structure
   coverage questions were tested in the existing single review call, but did not meet
   the declared cross-task adoption gate. They are archived experiment behavior, not
   an additional/default paid component. Ordinary review checks records and source units.
   The decoder and compiler share condition inheritance and target expansion. Whole
   list fields, including empty ones, are addressable for rejection and correction.
   [Controlled readback diagnostics](experiments/2026-09-16-tsg-structural-readback.md)
   found no incremental gain from including readback and bidirectional checks in the
   review request. That prompt addition was removed; its execution source survives
   only in the frozen experiment archive, not as an alternative active method.
   A semantic patch may replace/delete only
   affected records and their source/dependency closure, or add facts for affected
   source units. Unaffected records are preserved by the program. The same rejected
   claim under a surviving record ID cannot survive merely by changing its citation,
   provisional concept label, another field or list position.
   The merge preserves `unit_impacts` for source units already reviewed complete;
   only incomplete/rejected source units authorize changing their influence scope.
   No second critic or unlimited retries are added. Broad source units can still make
   the permitted repair region large. Changed wording is not mechanically certified
   equivalent; delete/recreate equivalence is not certified, and the model's positive
   verdict is not an independent guarantee.
5. **Compile without another semantic interpretation.** Record references produce
   input/output edges, requirement targets, owned guards and stated precedence.
   Task-wide scope is expanded mechanically. Preview compilation checks the draft;
   only the completed graph attempt can reach downstream assessment. Repair or review
   failure retains the failed task and any partial graph, without assessing its scopes.
6. **Assess candidate scopes separately.** The existing scope call consumes immutable
   source facts/relations. Operation context, required input origin and boundary
   premises must all be supported; a compatible role alone proves no applicability.
   Unknown participation is not represented as definite `input_unspecified` use.
   Each source unit declares source-cited `unit_impacts`, checked in the same review.
   Incomplete local units block affected operations; global/unlocalized uncertainty
   remains global. Recorded dependencies expand the affected set as a lower bound.
   Missing graph edges never prove unrelatedness. Candidate usability also requires
   a source review of its full dependencies and related assertions.

The usual path uses three provider calls: records, review and scope. At most five
calls are allowed, including one mechanical repair and one semantic patch. A failed
or wholly unresolved graph can end earlier. Native structured output is used for
records; review, patch and scope use ordinary JSON with local schema validation.
Atomic source records replace the previous inventory-plus-free-binding delivery;
they are not an extra research stage or an extra model pass.

## Evaluation boundaries

Report four distinct development results: critical semantic errors; required-meaning
coverage; source-checked usable scopes; and complete graph acceptance. Also report
provider/format failures and cost separately. Do not count graph assertions as
independent trials. Valid JSON, compiler checks, model self-review and replay each
establish different mechanical facts; none certifies semantic accuracy.

Full graph acceptance still requires source-faithful meanings, supported extras,
non-target requirements and correctly scoped conditions. Equivalent graph topologies
are allowed. An all-unknown graph does not meet coverage. Do not remove assigned
failures or regrade historical runs under a revised rule. A disputed reference is
recorded separately, not silently made authoritative or edited after inspection.

Historical development stability criteria were: a full six-case integration, three
fresh six-case repetitions, then a prospectively prepared untouched eight-task
natural set run twice with at least15/16 complete outputs and zero wrong decisive
states. These are development checks, not population accuracy guarantees. No new
stability/transfer claim follows from those pilots. The [current revision plan](tsg-revision-plan.md)
replaces that next-step target with one bounded candidate-level pilot, then at most
three exposed tasks if its key boundaries pass. Formal qualification is unchanged.

Current local scoring retains fixed source dependencies and source-cited assertion
impacts. Relevant endpoints cannot be waived. Report `candidate_metrics` alongside
`scope_quality`: acceptance precision (undefined for zero or uncertified acceptance),
certified-correct lower fraction, applicable reference recall and decisive coverage.
Extra accepted scopes remain listed outside the fixed reference denominator.
`pre_review_records`, `pre_review_contract` and `pre_review_graph` preserve the same
initial valid draft for source-reviewed transition counts; model approval is not a
reference answer. Unknown transitions remain separate from correct repairs.

## Current evidence and reproduction

The [cross-task comparison](experiments/2026-09-16-tsg-binding-coverage-transfer.md)
made16 review calls on eight authored variants of two previously exposed tasks,
with no extraction or repair calls. Detailed review detected3/4 corruptions versus
2/4 for ordinary review; both retained three unambiguous correct/equivalent variants.
A fourth proposed equivalent case had uncertain composite-parent scope and remains
unscored for false rejection, with original labels and raw judgments retained.
Deleted exception conditions were missed by both methods. The detailed component
was not promoted; the default ordinary review was restored. This ends the current
review-prompt iteration. Program readback and accepted-impact preservation remain.
Cost wasCNY3.484452. The110-case suite passed before execution and29 affected cases
passed after restoration; no new cases were added. Frozen16-call replay was exact.

The [binding-check diagnostic](experiments/2026-09-16-tsg-binding-checks.md) reused
the same five exposed structural variants. It detected6/6 focal corruptions and
retained4/4 correct/equivalent requirements plus the equivalent container. Two
unchanged background records were additionally rejected in the swapped-branch
version, so whole-graph consistency is not established. A sixth call correctly
repaired the expanded return targets but also narrowed an accepted source impact.
The final merge now preserves accepted impacts; offline replay of the same patch
matches the predeclared correct control exactly. Total cost wasCNY1.818732.
The unchanged110-case suite passed before execution and29 affected cases passed
after the merge correction. No fresh natural extraction or candidate assessment ran.

The [readback diagnostic](experiments/2026-09-16-tsg-structural-readback.md) completed
ten fixed requests on five structural variants of one exposed book task, costing
CNY1.900164 at the frozen rates. Both review prompts detected swapped guards, missed
deleted guards and expanded targets, and retained correct/equivalent focal bindings.
Detection was2/6 corrupted focal requirements for each prompt, with4/4 correct or
equivalent focal requirements retained. These dependent variants are diagnostics,
not natural-task accuracy. The conditional patch gate failed, so no repair was run.
The default paid prompt addition was removed; debug readback and empty-field repair
addresses remain. The unchanged110-case suite passed before execution and29 affected
cases passed after this final decision. Exact ten-request replay used no network.

The [composition/locality revision](experiments/2026-09-16-tsg-candidate-locality.md)
passes the unchanged110-case suite. One frozen book pilot compiled successfully in
three calls (CNY0.824160), but conditional returns still had task-wide scope and no
structured guards. The model approved every record; no patch or net correction
occurred. Fixed-reference anchor defects are reported separately from source errors.
The pilot stopped without expansion. Natural composite/local-unknown extraction
and independent candidate accuracy remain unestablished. A final scorer dependency
closure correction passed16 focused tests offline and did not regrade the frozen run.

The [atomic-record report](experiments/2026-09-16-tsg-atomic-records.md) records four
closed bounded batches using three already exposed tasks, frozen evaluation
dimensions, model settings and budgets. Completed graphs were0/3,2/3,1/1,0/1;
complete semantic acceptance remained zero. The updated review context was not
reached in the final live task because mechanical validation failed. The last local
diagnostic correction is tested offline only. This is implemented simplification,
not established semantic stability or evidence of a model ranking.
No protected tasks or formal study outcomes are consumed. Earlier closed-vocabulary
18/18 results and open-fact failures retain their original interpretation. The
[preceding report](experiments/2026-09-16-tsg-source-premise-repair.md) documents the
0/3 and0/2 results motivating this change.

Core reading order: this guide; `source_records.py`; `prompt_contract_extract.py`;
`prompt_contract.py`; `candidate_construction.py`; `prompt_contract_qualification.py`;
and the [reviewer guide](reviewer-guide.md). The development entry point is
`scripts/run_tsg_development.py`; formal acceptance remains blocked until independent
source qualification and an authorized frozen protocol exist.

Each frozen development batch includes inputs, exact execution source, provider
requests/responses and retained failures. The record trace permits exact mechanical
replay including review and patch. Independent source references and assertion review
remain necessary to judge the resulting semantics. The default suite remains110
cases in90 functions; update relevant boundary fixtures instead of expanding it.
