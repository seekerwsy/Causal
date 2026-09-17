# Current TSG construction and development evaluation

The active research protocol remains [SPECIFIED_DRAFT](protocol.md). The seven
scientific stages remain representation, prioritization, hypothesis freeze,
intervention/randomization, measurement, outcome assembly and inference/reporting.
This document describes development within representation, not formal qualification.

## One active construction path

```text
actual system/user input
  -> source records with participants, requirement composition, guards, scope and owned relations
  -> deterministic preview compilation
  -> one ordinary source review and at most one local patch
  -> deterministic compilation of the completed records
  -> separate candidate applicability/expression assessment
```

The model no longer receives a separate free binding task. Ordinary extraction and
`scripts/run_tsg_development.py` both enter `_attempt_source_graph`, which uses
`source_records.attempt_graph`. Old request/binding helpers serve record compilation
and retained fixtures; frozen old runs reproduce with their own execution archives.
They are not an alternative active workflow.

The [September 17 reliability checks](experiments/2026-09-17-tsg-reliable-construction.md)
keep independent obligation inventories experimental: complete output and valid
structure did not guarantee correct guards, scope or composition. Candidate delivery
now uses one exact requirement key per decision and program-restored bindings;
semantic eligibility still needs review. Bounded source-only construction agents are
development diagnostics, not an additional default reviewer or qualification.
The eight-task repetition compiled all 16 retained first drafts. Author audit
matched 88/96 fixed meanings and accepted 12/16 whole graphs; the bounded gate
failed. Four Pandoc policy mismatches retain a source-clause ambiguity, and four
privilege requirements have unresolved direct targets despite correct order edges.
This is not independent human gold, untouched transfer, or evidence of candidate
editability. No default constructor/reviewer change follows from that batch.
Continuing three of those constructions through fresh Codex reviews and the
existing local-patch interface completed all reviews, two patches and all three
final graphs. Fixed-reference correctness remained 19/23: neither the two Pandoc
predicate mismatches nor the two privilege binding ambiguities improved. The
agent workflow executes, but reliable semantic repair is not established.

1. **Prepare exact input.** `task_input.py` combines actual system/user messages and
   declared language. The program indexes source units; users do not manually number
   files. Generation must use the corresponding input. Recognized fixed system
   requirements are compiled once.
2. **Extract complete records.** Objects are declared once. Operations contain their
   required participants, roles, results and explicit execution guards. Each atomic
   requirement contains its complete predicate, modality, targets and conditions.
   Composite records preserve and/or/compound-not/opaque member structure. Only
   asserted complete requirements can support independent factors; conjunction carries
   its shared guards to members, while alternative/negated members stay non-independent.
   Requirements preserve thresholds, negations, exact result formats and variable names.
   In open development, the program assigns new concept identities from exact full
   definitions and node types; provisional model labels cannot merge different atoms.
   Exact unique known meanings retain their supplied IDs. Frozen concepts are unchanged.
   `scope_kind=task` retains an overall runtime-task boundary without producing
   per-operation obligations. `targets` names direct local targets, including a
   source-supported aggregate function when the requirement concerns its return,
   interface or total resource use. `each` retains an explicit universal rule with
   an open `target_class` and zero/one enclosing operation; it never treats extracted
   instances as the complete domain. `implementation` binds generation requirements.
   AND/OR/NOT parents use `composite`, carry shared guards and preserve member
   structure without adding a separate target obligation. Leaves retain exact targets.
   Every listed target receives the whole predicate; a temporal counterpart is not
   another direct target. A runtime atom's `relations` list owns its required
   `precedes` operands. These rows inherit the owner's modality, guards and composition.
   Contract and graph `requirement_relations` retain ownership; they never become
   unconditional ordinary edges. Composite parents cannot add their own relations.
   Operation `precedes` is reserved for independently supported context. Separate
   source statements may support the same pair, but one declaration cannot be copied
   into both locations. Removing a policy must preserve separately supported context.
   Whole-task/universal scopes survive in contract and graph `requirement_scopes`.
   They may support a whole-boundary policy after semantic review, without a local
   instance projection. They cannot certify an unrelated local candidate or local
   negative. Complete OR/NOT policies require a common member binding and a reviewed
   single policy meaning; opaque or differing member bindings remain unresolved.
   A nested requirement guard produces only condition-to-requirement edges. It cannot
   also gate an operation unless the model separately asserts an execution condition.
   An absent operation execution guard is not a claim that the operation executes on
   every path. Prompt TSG is not an execution trace. In contrast, a requirement's
   empty guard supplies no conditional restriction on that requirement's binding.
   A function's outward return contract concerns normal returns, not exceptional
   exits; exceptions do not alone require an extra success guard. Explicit business
   branches such as found/not-found still require distinct structural conditions.
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
   Extraction, review, patch and readback share `source_records.record_semantics`,
   including the distinction between direct targets and owned relation operands.
   Review receives the already compiled `effective_unit_impacts` and a canonical
   operation-ID dictionary alongside the raw records. Its completeness judgment
   concerns this actual effective table: a dependency already supplied by the
   compiler is not a missing graph dependency. The computed lower bound is not
   source truth; unsupported or still-missing impacts remain reviewable. No extra
   compilation, reviewer or model round is introduced by passing this view.
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
   input/output edges, requirement targets, owned guards and separately retained
   requirement relations. Only independent context produces ordinary precedence edges.
   Task-wide scope is never broadcast. Preview compilation checks the draft;
   only the completed graph attempt can reach downstream assessment. Repair or review
   failure retains the failed task and any partial graph, without assessing its scopes.
6. **Assess candidate scopes separately.** The existing scope call consumes immutable
   source facts/relations. Operation context, required input origin and boundary
   premises must all be supported; a compatible role alone proves no applicability.
   Unknown participation is not represented as definite `input_unspecified` use.
   `atom` establishes a structural leaf only; factor review must justify the single
   changeable predicate, its source-bound target/guards and preserved requirements.
   Frozen `feature_scope_selectors` retain scope kind, universal class, expression
   kind and policy-internal guards. Task matching reads only independent geometry;
   a policy-only guard does not become an additional source-context prerequisite.
   An order policy also freezes exact `policy_relations`. Its endpoints must resolve
   independently and uniquely, but the order need not already hold for applicability.
   Positive expression must match direction, endpoints and the complete binding.
   OR/NOT members with different relation envelopes remain represented but unresolved
   for candidate projection; they are not flattened into simultaneous obligations.
   Source dependencies and edit checks include both operands. Removing a target
   owner may remove its relations; other owners and independent ordinary relations
   remain non-target invariants. This preserves semantics, not proof of editability.
   The retained two-task complete repair round blocked both whole-policy deletions:
   its editor protected policy-introduced action/result anchors. The current bounded
   revision permits an explicitly reviewed candidate `applicability_scope` distinct
   from its unchanged complete policy signature. Selection uses the background;
   positive expression still requires the actual policy targets, guards and order.
   Missing policy operands alone never establish absence. Background selection must
   use frozen source meanings and existing semantic review of independent support.
   No alternate anchor is inferred from a remaining relation endpoint.
   At editing time only, the existing reviewed realization may supply a local
   `source_review.edit_scope`. Default preservation remains. Explicit policy-only
   operation/object facts and their reviewed input/output relations can change with
   the enabled policy. Shared requirements, independent order, background coordinates
   and other scope assessments stay protected; relevant unknown support blocks the
   edit. Unchanged unrelated unknowns do not invalidate the entire graph. Root
   membership is compiled structure, not another model judgment. This adds no global
   ownership field, extraction gate, second graph or reviewer. Authored controls
   demonstrate the mechanical ADD/REMOVE boundary, not automatic attribution accuracy
   or qualification of the two historical natural edits.
   The first natural model-driven background check proposed a policy-dependent
   coordinate for privilege lowering (caught by candidate review) and returned
   unresolved for registration. No candidate passed, so its planned construction
   and edit steps did not run. The request's original-scope preservation wording
   may also contribute to the confusion; this result does not isolate model ability.
   The default compact interface now makes the policy binding read-only and requires
   an independently cited background per binding. The subsequent two-task check used
   11 fresh Codex steps: privilege lowering passed candidate review and both fresh
   graph/state assessments; registration's background wrongly included the hashed
   result and was rejected. Experimental adapter corrections and a source-continuity
   check for different citation lengths then let the same saved privilege pair pass
   REMOVE/inverse ADD and independent replay. The original failures remain saved.
   No model was resampled, and only this one exposed edit pair was demonstrated.
   The `objects` selector preserves an exact direct object boundary without requiring
   an invented operation target. Root is only its coordinate anchor; object uses
   do not broaden it. Object identity and relevant dependencies must be decisive.
   Scope assessment checks the complete policy at that boundary, including exact
   positive guard bindings and independent applicability. Root existence or a
   vacuously empty class is no applicability proof. Whole scopes and composition
   enter assertion review and non-target edit checks, not merely the visualizer.
   A reused factor definition does not certify each new occurrence. Editing continues
   to read the complete original input, including unresolved text. Factor expression
   is judged over effective system and user messages together: repetition/removing a
   user repetition does not establish an absent-to-present/present-to-absent change.
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

The [complete-policy natural check](experiments/2026-09-17-complete-policy-natural.md)
completed firmware-upload and file-download graphs in five Qwen Max calls. Its one
Qwen Flash candidate call truncated at 8,192 tokens; no catalogue or edit followed.
Source audit found a missing failure guard and a directory used as the constrained
path. The partial candidate output also selected ordinary interfaces/returns and
re-guessed graph targets. Local old/new diagnostics permit nine/ten of its seventeen
complete leading items structurally, but the additional conditional exception is
non-target functionality, not a valid security-factor gain. This does not establish
automatic improvement. All six requests replay exactly; conservative cost is
CNY1.926796 and remaining authorization CNY4.903512. No further sample was drawn.

The [explicit-boundary revision](experiments/2026-09-17-tsg-boundary-revision.md)
removes task-to-operation broadcast and retains whole-task/universal scope in the
graph. Two authored controls demonstrate the compiler correction. A fresh paired
old/new comparison on the exposed pandoc and book tasks completed all four graphs
in ten calls (CNY3.169692). Both versions kept the two API prohibitions in one atom;
zero of the two fixed single-API probes was usable, so no prompt edit ran. Revised
pandoc separated the global exception constraint but omitted the function-name
requirement. Book branches survived in both versions. No overall automatic quality
or stability improvement was established. The unchanged101-case reviewer suite
passed in a clean export; both frozen model executions replay exactly offline.
New scope semantics are active; old results retain their archived execution code.

The [three-scheme extraction diagnostic](experiments/2026-09-17-tsg-extraction-comparison.md)
compared current full records, focused bindings and inventory-then-binding on the
same exposed pandoc task, twice per scheme. Eight calls completed for CNY2.444208.
All six final outputs kept both API prohibitions in one atom. Focused extraction
cost less but varied in omissions, guards and effective presentation constraints;
staged extraction retained more prose while expanding targets in one repetition
and moving runtime obligations to the generation layer in the other. Auxiliary
relation omissions also limited the projected schemes' coverage. This isolated
extraction, not review/repair or a complete candidate pipeline. No alternative was
promoted. The one-task source audit and exact offline replay are development
evidence, not population accuracy, independent qualification or model ranking.

The [current-path validation](experiments/2026-09-16-atomic-current-workflow.md)
ran the exposed pandoc task under the actual prepared input. Four baseline calls
produced a graph and repaired missing exception/logging guards, but retained two
API prohibitions in one atom and combined separately scoped error obligations.
A single prompt-clarification recheck truncated before compilation; it was not
adopted, and the default instructions were restored. Five calls cost CNY3.089772
under conservative accounting. Both frozen executions replay exactly offline.
Correcting two baseline records locally, with two added atoms, allowed the existing
candidate draft and reviewed rewrite to handle the fixed subprocess factor while
retaining the other prohibition. This author correction is not automatic candidate
discovery or independent qualification. The next research decision concerns a
bounded downstream comparison with explicit controls and independent measurements,
keeping the automatic-graph failure and authored correction distinct. No more
review-prompt iteration is scheduled by this diagnostic.

The latest [single-requirement edit diagnostic](experiments/2026-09-16-atomic-shell-removal.md)
found a source-audited feasible REMOVE in one exposed pandoc task. Removing only the
subprocess prohibition preserved the os.system prohibition and non-target behavior.
The existing reviewed-rewrite interface handled their shared sentence; no production
mechanism was added. The historical automatic graph instead deleted only `with
shell=True`, leaving a broader prohibition while reporting an intended absent state.
Evidence spans are not automatically editable semantic units, and intended states
are not measured fidelity. This was an author-audited interface probe, not fresh
extraction, automatic candidate discovery or independent intervention qualification.
That result motivated the current-path check above. No additional review component
was promoted.

The earlier [Atomic interface diagnostic](experiments/2026-09-16-atomic-candidate-interface.md)
replayed three exposed tasks without provider calls. Correct requirement-only
guards could not cross the candidate context gate, but those return/exception
requirements were non-target functionality, not valid editable security factors.
A directory-containment probe mechanically removed a security sentence while
retaining required outside-directory rejection. No intervention was approved.
That negative result motivated the independently editable example above.
Draft construction is not semantic approval.

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
remain necessary to judge the resulting semantics. The current Atomic default suite
has 105 cases in 85 functions. One whole-policy projection/edit case adds eight
authored semantic contrasts; historical counts above retain their original meaning.
See the [bounded projection check](experiments/2026-09-17-complete-policy-projection.md).
These are implementation checks, not automatic-extraction accuracy or natural coverage.
