# Contract content cleaning protocol

This is the single active content-cleaning successor to the reviewer task-unit
bundle frozen at commit `1d1654e`. It changes no task identity, source prompt,
near-duplicate group, method, Prompt TSG, experimental role, arm, generated
program, Oracle result, or outcome.

## Frozen boundary

Before any content call, `reserve-future-evaluation` selects the minimum task
unit ID from every near-duplicate group whose members are all `UNASSIGNED`.
Selection sees only task IDs, group IDs, and prior roles. The reservation is not
a formal Discovery, qualification, or Confirmation role. It permits only blind
curation until a later prospectively frozen allocation.

The cleaning runner sends source prompts and contracts to the frozen Bailian
curators. Requests exclude CWE labels, readiness, roles, arms, generated code,
Oracle results, and outcomes. The operator reviews only aggregate counts. Every
task processed by this path receives the exposure category
`CONTRACT_REPAIR_VIEWED`; that category does not imply method-development
exposure.

## Two producer modes

Contracts whose effective prior review is `faithful` enter
`EVIDENCE_BACKFILL_ONLY`. Their semantic fields are immutable. The producer
must bind every non-empty value to one or more exact source spans. Failure to
bind escalates the task to semantic repair without reclassifying the source.

Contracts whose effective review is not faithful, plus escalations, enter
`SEMANTIC_REPAIR`. The producer may replace contract content under one source-
only protocol and must bind every resulting value to exact evidence.

Offsets are measured over the UTF-8 bytes of the exact `natural_prompt`:

```text
source_prompt_sha256
start_byte
end_byte
quoted_text
span_sha256
```

There is no silent truncation. A resolved contract has 1--32 requirements. A
source with more irreducible requirements or an internal conflict is marked
ambiguous rather than shortened.

## Independent review and terminal quality

The independent reviewer receives only the prompt, proposed contract, and
evidence. It separately decides contract faithfulness, evidence support, and
source-specification sufficiency. Producer failure remains nonterminal and can
never be converted into source insufficiency.

Only a faithful, evidence-supported contract can receive a terminal quality
decision:

| Source disposition | Quality disposition |
| --- | --- |
| sufficient | `QUALITY_INCLUDED` |
| insufficient | `QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION` |
| defect | `QUALITY_EXCLUDED_SOURCE_DEFECT` |
| uncertain | nonterminal; independent adjudication required |

The migration audit is `contract-repair-ledger.jsonl`; it is not an additional
quality authority. Final authority remains the reviewer bundle's
`functional-contracts.jsonl`, `task-quality.jsonl`, and `task-roles.jsonl`.

## Execution order

```powershell
prompt-mechanism-study curate reserve-future-evaluation BASE RESERVATION `
  --producer-commit COMMIT

prompt-mechanism-study curate contract-content-proposals BASE PROPOSALS `
  --producer-commit COMMIT --workers 6 --stop-after-evidence

prompt-mechanism-study curate contract-semantic-repairs `
  BASE PROPOSALS/evidence REPAIRS --producer-commit COMMIT --workers 6

prompt-mechanism-study curate contract-repair-evidence `
  BASE REPAIRS/final REPAIR-EVIDENCE --producer-commit COMMIT --workers 6

prompt-mechanism-study curate assemble-contract-content `
  BASE PROPOSALS/evidence REPAIRS/final REPAIR-EVIDENCE/final PROPOSALS-FINAL `
  --producer-commit COMMIT

prompt-mechanism-study curate contract-content-review `
  BASE PROPOSALS-FINAL REVIEW --workers 6

prompt-mechanism-study curate finalize-contract-content build FINAL `
  --base-bundle BASE --proposals-root PROPOSALS-FINAL `
  --reviews-root REVIEW/final --reservation-root RESERVATION `
  --producer-commit COMMIT

prompt-mechanism-study curate finalize-contract-content verify FINAL
```

Semantic repair and repaired-contract evidence binding each use one task unit
per provider request. The first LLM call decides only the semantic contract;
deterministic code then constructs its exact target list, and the second call
only binds source spans to that immutable list. Run
one batch of each producer mode and one review batch before scaling. Runs
are resumable only from closed successful batches with the same frozen plan.
Raw requests and provider responses remain in the run directory; credentials
are never recorded.

The finalizer accepts no nonterminal review. It converts the evidence to no
other offset system, recomputes quality and the derived readiness view, records
`CONTRACT_REPAIR_VIEWED`, and carries the prompt-blind reservation into the
role record without assigning a formal role. Its independent verifier rechecks
each evidence span directly against the UTF-8 prompt bytes.

## Completion gate

The data foundation is complete only when all 2,165 task units have exactly one
current evidence-complete contract, all quality rows are one of the three
terminal dispositions above, the six former independent-review cases are
closed, role/exposure and near-duplicate firewalls still hold, two final builds
are byte-identical, and the verifier/default reviewer suite pass. Prompt TSG,
formal roles, arms, generated code, and outcomes must remain absent.
