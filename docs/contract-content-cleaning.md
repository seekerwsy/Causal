# Contract content cleaning protocol

This is the single active content-cleaning successor to the reviewer task-unit
bundle frozen at commit `1d1654e`. Ordinary contract repair changes no task identity, source prompt,
near-duplicate group, method, Prompt TSG, experimental role, arm, generated
program, Oracle result, or outcome.

For study reproduction, start with the released frozen data bundle and run
`prompt-mechanism-study curate finalize task-units verify BUNDLE`. Rebuilding the
data foundation is separate, outcome-blind preparation with four CLI groups:

| Group | Responsibility |
|---|---|
| `curate prepare` | source semantics, clusters, contract proposals and blind reservations |
| `curate review` | independent contract and binding review, disagreement closure and merging |
| `curate repair` | conditional correction of nonterminal contracts or evidence |
| `curate finalize` | proposal assembly and final task-unit bundle construction/verification |

The arguments and underlying functions are unchanged. The old flat command
names have no live aliases; historical execution logs retain their original
commands. Archived single-provider content review is unavailable from this CLI
and cannot supply terminal quality decisions.

## Frozen boundary

Before any content call, `reserve-future-evaluation` selects the minimum task
unit ID from every near-duplicate group whose members are all `UNASSIGNED`.
Selection sees only task IDs, group IDs, and prior roles. The reservation is not
a formal Discovery, qualification, or Confirmation role. It permits only blind
curation until a later prospectively frozen allocation.

The producer stages may use the frozen Bailian curator, but producer output is
never a quality authority. Final content review uses three local Codex subagent
slots under the same frozen review prompt. Review packets contain only task ID,
the exact source prompt, and the proposed contract with evidence. They exclude
the producer's source assessment, declared-language metadata, CWE labels,
readiness, roles, arms, generated code, Oracle results, and outcomes. The
operator reviews only aggregate counts. Every task processed by this path receives the exposure category
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

`source_prompt_sha256` is the repository content hash of the canonical JSON
string, not the hash of the unquoted UTF-8 bytes. Response-envelope
instructions such as `only return code` are not generated-software behavior
and therefore do not enter the functional contract. These two boundaries are
shared by extraction, repair, review, and verification.

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
quality authority. For the immutable v5 baseline, the authoritative files are
`functional-contracts.jsonl`, `task-quality.jsonl`, and `task-roles.jsonl`.

## Execution order

```powershell
prompt-mechanism-study curate prepare reservation BASE RESERVATION `
  --producer-commit COMMIT

prompt-mechanism-study curate prepare content BASE PROPOSALS `
  --producer-commit COMMIT --workers 6 --stop-after-evidence

prompt-mechanism-study curate repair semantic `
  BASE PROPOSALS/evidence REPAIRS --producer-commit COMMIT --workers 6

prompt-mechanism-study curate repair evidence `
  BASE REPAIRS/final REPAIR-EVIDENCE --producer-commit COMMIT --workers 6

# Run only when the first evidence pass contains unresolved non-empty targets.
# Empty-target contracts close deterministically; only disputes reach the reviewer.
prompt-mechanism-study curate repair adjudicate-evidence `
  BASE REPAIRS/final REPAIR-EVIDENCE/final REPAIR-EVIDENCE-ADJUDICATED `
  --producer-commit COMMIT --workers 6

# Run only when independent evidence adjudication still rejects non-empty values.
prompt-mechanism-study curate repair correct-evidence `
  BASE REPAIRS/final REPAIR-EVIDENCE-ADJUDICATED/final CONTRACT-CORRECTIONS `
  --producer-commit COMMIT --workers 6

# Use only after bounded correction still leaves span-localization disputes.
prompt-mechanism-study curate repair materialize-evidence `
  BASE CONTRACT-CORRECTIONS/final CONTRACT-CORRECTIONS/final REVIEW-EVIDENCE `
  --producer-commit COMMIT

prompt-mechanism-study curate finalize proposals `
  BASE PROPOSALS/evidence REVIEW-EVIDENCE/final REVIEW-EVIDENCE/final `
  PROPOSALS-FINAL `
  --producer-commit COMMIT

prompt-mechanism-study curate review prepare `
  BASE PROPOSALS-FINAL REVIEW-PACKETS --producer-commit COMMIT

# Three reviewer slots independently populate DECISIONS from their frozen packets.
prompt-mechanism-study curate review seal `
  REVIEW-PACKETS DECISIONS INITIAL-REVIEW

# The third reviewer slot blindly reviews every packet emitted for disagreement.
prompt-mechanism-study curate review finalize `
  INITIAL-REVIEW ADJUDICATION-DECISIONS PROPOSALS-FINAL REVIEW-ROUND-1

# Nonterminal contracts and contracts rejected by a deterministic protocol
# invariant are repaired. Repair decisions are source-only; exact whole-prompt
# evidence remains pending until independent re-review.
prompt-mechanism-study curate repair prepare `
  BASE PROPOSALS-FINAL REVIEW-ROUND-1 REPAIR-PACKETS `
  --producer-commit COMMIT

# Three producer slots populate REPAIR-DECISIONS from the frozen repair packets.
prompt-mechanism-study curate repair finalize `
  BASE PROPOSALS-FINAL REVIEW-ROUND-1 REPAIR-PACKETS REPAIR-DECISIONS `
  PROPOSALS-REPAIRED --producer-commit COMMIT

# Re-review only contracts whose content identity changed in the repair round.
prompt-mechanism-study curate review prepare `
  BASE PROPOSALS-REPAIRED REPAIR-REVIEW-PACKETS --producer-commit COMMIT `
  --nonterminal-reviews-root REVIEW-ROUND-1

prompt-mechanism-study curate review seal `
  REPAIR-REVIEW-PACKETS REPAIR-REVIEW-DECISIONS REPAIR-INITIAL-REVIEW

prompt-mechanism-study curate review finalize `
  REPAIR-INITIAL-REVIEW REPAIR-ADJUDICATION-DECISIONS `
  PROPOSALS-REPAIRED REPAIR-REVIEW

prompt-mechanism-study curate review merge `
  REVIEW-ROUND-1 REPAIR-REVIEW PROPOSALS-REPAIRED REVIEW-FINAL

# REVIEW-FINAL/report.json must report nonterminal_count=0. If not, repeat only
# the remaining nonterminal subset; never relabel or silently omit it.

prompt-mechanism-study curate finalize task-units build FINAL `
  --base-bundle BASE --proposals-root PROPOSALS-REPAIRED `
  --reviews-root REVIEW-FINAL --reservation-root RESERVATION `
  --producer-commit COMMIT

prompt-mechanism-study curate finalize task-units verify FINAL
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
role record without assigning a prospective formal role. Historical frozen
exposure roles remain intact. Its independent verifier rechecks each evidence
span directly against the UTF-8 prompt bytes. The repair ledger's
`source_specification_disposition` is the repair producer's diagnostic; the
review record and `task-quality.jsonl` remain the final quality authority.

## Completion gate

The data foundation is complete only when all 2,165 task units have exactly one
current evidence-complete contract, all quality rows are one of the three
terminal dispositions above, every dual-review disagreement has a blind third
decision, role/exposure and near-duplicate firewalls still hold, two final builds
are byte-identical, and the verifier/default reviewer suite pass. Prompt TSG,
prospective formal-role assignments, arms, generated code, and outcomes must
remain absent.

## Completed ordered source review

The active source-only preparation is
`data/dataset-curation/research-source-use-v2`. Its four disjoint cohorts are
complete in the authorized order. These reviews establish current source
contracts, native assertion mappings and exact candidate sufficiency; they grant
no measurement qualification or scientific claim. The immutable v5 baseline,
66 exposed tasks and 56 qualification reservations retain their original
identities and restrictions.

| Cohort | Tasks | Current contract quality: included / insufficient / defect | Candidate records: Atomic / Pair | Source-sufficient candidates |
|---|---:|---|---:|---:|
| Restored upstream inputs | 124 | 88 / 31 / 5 | 214 / 36 | 5 Atomic |
| Unchanged insufficient sources with native assets | 124 | 61 / 61 / 2 | 178 / 4 | 3 Atomic |
| Other unchanged insufficient sources | 1,055 | Original insufficient quality retained | 850 / 72 | 1 Atomic |
| Unchanged source defects | 156 | 56 / 60 / 40 | 100 / 28 | 2 Atomic |

The first, second and fourth cohorts have 404 faithful, evidence-supported
current contracts with no nonterminal decisions or required repairs remaining.
Their eight complete independent review rounds preserve raw dual judgments,
blind third judgments for disagreements, and fresh re-review of required repairs.
The third cohort received candidate-level source review and retained its original
quality. Across all 2,165 prepared tasks, current quality is 871 included,
1,246 insufficient and 48 source defects; 789 included tasks are unexposed and
unreserved. Original quality records remain immutable.

All 1,459 cohort tasks have 32,098 context-group decisions and 1,482 exact
candidate records. Eleven Atomic records on 11 distinct tasks pass source
sufficiency only. The proposal book defines 22 groups containing 48 Atomic and
eight Pair proposals, with concrete meanings currently limited to Python.
The 964 non-Python cohort tasks retain explicit missing-definition states.
`NO_SOURCE_CONTEXT` does not establish feature absence or universal ineligibility.
A Pair is reviewed independently of whether either Atomic factor is selected
or supported. The other 584 unchanged quality-included available tasks have not
received this follow-up. Complete functionality and joint success remain unknown
where the source does not support complete functional judgment.

Native content review covers 284 tasks and all 662 of their asset bindings.
The restored cohort's 199 bindings provide setup, dependencies or no assertions,
with zero assertion mappings. The second cohort's 359 bindings provide 368
functional and 90 security assertion mappings. The fourth cohort's 104 bindings
provide 82 functional and 33 security assertion mappings.
Each mapping binds exact source and asset evidence. These are correspondences,
not passing tests or complete coverage. No asset was executed and no measurement
qualification or formal admission was granted.

Use `curate prepare restored-contracts BASE SOURCE-USE QUALIFICATION-RESERVATIONS
SECODEPLT-SOURCE OUTPUT --producer-commit COMMIT` for restored-input proposals.
It checks frozen source bytes, replays the upstream default prompt and binds
exact UTF-8 evidence. A changed input cannot inherit its parent's contract review.
Whole-prompt evidence remains pending independent semantic review. Continue with
the existing `curate review prepare`, `seal`, `finalize` and conditional
`curate repair prepare` / `finalize` commands. Pass `--source-use-bundle SOURCE-USE`
and `--reservation-bundle QUALIFICATION-RESERVATIONS` for review/repair preparation
and repair finalization. Packets withhold source metadata, prior quality and
producer assessments. The frozen review prompt is
`contract-content-review-v1.txt`, SHA-256
`91e105f57840d3f81f7108de65c0b18392cccc48ef3980e6413abec02bd87b29`.

`curate review verify PROPOSALS PACKETS DECISIONS INITIAL ADJUDICATIONS REVIEWS`
independently reconstructs assignments, raw judgments, disagreements, third
judgments and published dispositions. After required repairs close, pass each
complete round to `curate prepare source-use` using repeated
`--contract-review-round PROPOSALS PACKETS DECISIONS INITIAL ADJUDICATIONS REVIEWS`.
The package keeps original review records and binds current measurement contracts
to the freshly reviewed input. Changed but unreviewed proposals block preparation.

Native review follows `source-native-asset-review-v1.txt`; candidate review follows
`source-candidate-context-screen-v1.txt`, `source-candidate-sufficiency-review-v1.txt`
and `source-candidate-policies-v1.json`. Pass `--native-asset-reviews FILE`,
`--candidate-context-reviews FILE` and `--candidate-reviews FILE` on the same
source-use command. Independent verification reconstructs source spans, current
contract and policy identities, every native binding, all context groups and
exactly the required five-axis candidate judgments. Native assets must not supply
new model-visible task requirements. Implementation freedom alone is not source
insufficiency, and no preparation step adds independent task units.

Full replay of all seven raw source roots, two pinned archives and eight
contract-review rounds returns `SOURCE_USE_VERIFIED`. The released manifest
SHA-256 is
`2015d760cbeaacff16e701ad25a507e5973960a31b0ecd7de8d4b769bf7a741c`.
Its report records exact reproduction inputs and the environment. The embedded
review lineage supports independent verification without the original development
review directories. Earlier immutable preparations and per-slot raw decisions
remain provenance, outside the current reviewer entry point.

## Completed 2026-09-01 execution

The all-task subagent execution is frozen locally under
`.codex-runtime/subagent-full-review`. An earlier anchored v1 attempt is invalid
and supplies no decisions to the final lineage. The active lineage used
unanchored v2 packets, bounded source-only repair, repaired-subset re-review,
and the v3/v4 clarifications above. A final all-contract invariant scan found
87 response-envelope residues and 19 included-but-ambiguous contracts, with one
overlap. Commit `4acfb5c` reopened exactly those 105 contracts; fresh repair
producers and separate dual reviewers repaired and re-reviewed them. Five
remaining extraction errors received one final bounded repair and fresh dual
review. No selection used a role, arm, generated program, Oracle, or outcome.

The terminal review covers all 2,165 task units:

| Quality disposition | Count |
| --- | ---: |
| `QUALITY_INCLUDED` | 720 |
| `QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION` | 1,284 |
| `QUALITY_EXCLUDED_SOURCE_DEFECT` | 161 |

Every final contract is `faithful`, every evidence binding is `supported`, and
`nonterminal_count=0`. The two independent final builds
`final-data-v7-a` and `final-data-v7-b` contain the same ten files byte for
byte. Their common bundle/manifest SHA-256 is
`33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`.
The independent verifier returns
`VERIFIED_DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED`.

The canonical baseline copy is tracked byte-for-byte at
`data/dataset-curation/reviewer-task-unit-dataset-v5`. The ignored A/B build
directories remain execution provenance only; the tracked copy replays the same
baseline verifier status and manifest hash. Current prepared prompts, contracts
and source-use decisions come from the v2 preparation described above.

The terminal corpus contains no response-envelope requirement, no included
contract with unresolved semantics, and no stale contract-quality diagnostic
in readiness. Technical readiness remains separate and currently contains 101
task units under the existing mechanism, Oracle, runtime, and functionality
stack.

This is a completed data-quality foundation, not a formal experiment freeze.
Prompt TSG remains `NOT_GENERATED_PENDING_METHOD_FREEZE`; prospective formal
roles, arms, generated programs, Oracles, outcomes, and effect claims remain
absent. Historical `FROZEN_HISTORICAL` exposure roles are preserved.
