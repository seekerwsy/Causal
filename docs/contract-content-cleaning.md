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

The producer stages send source prompts and contracts to the frozen Bailian
curators. Final content review uses three local Codex subagent slots under the
same frozen review prompt. Review packets exclude CWE labels, readiness, roles,
arms, generated code, Oracle results, and outcomes. The operator reviews only
aggregate counts. Every task processed by this path receives the exposure category
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

Each task receives two independent subagent reviews. Reviewer assignment is a
frozen hash of `task_unit_id`; the two reviewers receive only the prompt,
proposed contract, and evidence. They separately decide contract faithfulness,
evidence support, and source-specification sufficiency. When those three fields
disagree, the third reviewer receives the same blind task packet without either
prior decision and supplies the final adjudication. Producer failure remains
nonterminal and can never be converted into source insufficiency.

The collaboration backend does not expose a seed-stable public replay API.
Reproducibility therefore rests on the frozen prompt, complete blind packets,
per-reviewer decisions, assignment plan, and deterministic merger rather than
an assertion that a future model call will reproduce identical prose. These
curation judgments define the released data foundation; they are not experimental
outcomes or evidence for an RQ effect.

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

# Run only when the first evidence pass contains unresolved non-empty targets.
# Empty-target contracts close deterministically; only disputes reach the reviewer.
prompt-mechanism-study curate adjudicate-contract-repair-evidence `
  BASE REPAIRS/final REPAIR-EVIDENCE/final REPAIR-EVIDENCE-ADJUDICATED `
  --producer-commit COMMIT --workers 6

# Run only when independent evidence adjudication still rejects non-empty values.
prompt-mechanism-study curate correct-unbound-contract-evidence `
  BASE REPAIRS/final REPAIR-EVIDENCE-ADJUDICATED/final CONTRACT-CORRECTIONS `
  --producer-commit COMMIT --workers 6

# Use only after bounded correction still leaves span-localization disputes.
prompt-mechanism-study curate materialize-contract-review-evidence `
  BASE CONTRACT-CORRECTIONS/final CONTRACT-CORRECTIONS/final REVIEW-EVIDENCE `
  --producer-commit COMMIT

prompt-mechanism-study curate assemble-contract-content `
  BASE PROPOSALS/evidence REVIEW-EVIDENCE/final REVIEW-EVIDENCE/final `
  PROPOSALS-FINAL `
  --producer-commit COMMIT

prompt-mechanism-study curate prepare-subagent-contract-review `
  BASE PROPOSALS-FINAL REVIEW-PACKETS --producer-commit COMMIT

# Three reviewer slots independently populate DECISIONS from their frozen packets.
prompt-mechanism-study curate seal-initial-subagent-contract-review `
  REVIEW-PACKETS DECISIONS INITIAL-REVIEW

# The third reviewer slot blindly reviews every packet emitted for disagreement.
prompt-mechanism-study curate finalize-subagent-contract-review `
  INITIAL-REVIEW ADJUDICATION-DECISIONS PROPOSALS-FINAL REVIEW

prompt-mechanism-study curate finalize-contract-content build FINAL `
  --base-bundle BASE --proposals-root PROPOSALS-FINAL `
  --reviews-root REVIEW/final --reservation-root RESERVATION `
  --producer-commit COMMIT

prompt-mechanism-study curate finalize-contract-content verify FINAL
```

Semantic repair and repaired-contract evidence binding each use one task unit
per provider request. Only the semantic contract is consumed from the first
LLM call; the v1 producer sometimes emitted an auxiliary evidence array, which
is deterministically discarded and counted. Code then constructs the exact
target list, and the second call alone supplies the frozen source spans. Run
one batch of each producer mode and one review packet before scaling. Subagent
decisions are resumable only by exact packet ID under the same frozen plan.
Raw producer requests and provider responses and all subagent packet decisions
remain in the closed run directory; credentials are never recorded.

Evidence binding is vacuously complete when the immutable contract contains no
non-empty values. If the first binder disputes a non-empty contract, only that
subset is sent once to the independent reviewer model. Remaining disputes stay
nonterminal and require contract correction; they are never relabeled as source
insufficiency or silently dropped.

Contract correction is restricted to those remaining non-empty disputes. It
freezes a source-only replacement contract before a separate evidence call and
then merges only those task IDs back into the full repair/evidence population.
Until a dispute is either bound or explicitly marked for whole-prompt semantic
review, the final proposal assembler refuses the bundle.

After bounded correction, a remaining localization dispute may receive exact
whole-prompt UTF-8 spans with status `full_prompt_pending_review`. This is not a
semantic support decision. The independent final reviewer must still judge both
contract faithfulness and whether the cited prompt supports every value. The
fallback status and route are retained in the repair ledger; any unsupported
review remains nonterminal.

The finalizer accepts no nonterminal review. It converts the evidence to no
other offset system, recomputes quality and the derived readiness view, records
`CONTRACT_REPAIR_VIEWED`, and carries the prompt-blind reservation into the
role record without assigning a formal role. Its independent verifier rechecks
each evidence span directly against the UTF-8 prompt bytes.

## Completion gate

The data foundation is complete only when all 2,165 task units have exactly one
current evidence-complete contract, all quality rows are one of the three
terminal dispositions above, every dual-review disagreement has a blind third
decision, role/exposure and near-duplicate firewalls still hold, two final builds
are byte-identical, and the verifier/default reviewer suite pass. Prompt TSG,
formal roles, arms, generated code, and outcomes must remain absent.
