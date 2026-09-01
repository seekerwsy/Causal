# All-task subagent contract-content review

## Purpose and evidence boundary

This run completes content-quality curation for all 2,165 task units. It does
not freeze Prompt TSG, a mechanism hypothesis, an experimental role, an arm, a
generator, an Oracle outcome, or a scientific effect. All packet construction,
review, repair, and aggregation were blind to those downstream fields.

## Valid lineage

The earlier v1 review attempt exposed producer assessments and is invalid. No
v1 decision is consumed here. The valid lineage begins with commit `363991e`
and unanchored v2 packets containing only `task_unit_id`, `source_prompt`, and
`proposed_contract`.

The initial dual review produced 4,330 decisions. There were 1,159 agreements
and 1,006 blind third-person adjudications. The first freeze left 1,060 terminal
and 1,105 nonterminal contracts. Source-only subagents repaired only the
nonterminal set; independent dual review plus blind adjudication made 1,017 of
those terminal, leaving 88.

A second bounded repair reduced the substantive residue. Its review exposed a
protocol mismatch: the repair prompt excluded response-envelope instructions
from software behavior, while the review prompt did not say so explicitly.
Commit `9b3b820` aligned that boundary and only the 69 affected nonterminal
contracts were re-reviewed. The final three cases exposed a second ambiguity:
reviewers could mistake the repository's canonical-JSON content hash for a raw
UTF-8 string hash. Commit `96023c5` made the hash definition explicit. The
remaining three contracts, then the final single CSRF contract, were repaired
and independently re-reviewed.

The final independent audit then scanned every contract, not only the prior
nonterminal subset. It found 87 response-envelope residues and 19 included
contracts still marked `ambiguous`, with one overlap. Commit `4acfb5c` widened
the common repair selector and added finalizer gates. Exactly those 105
contracts were repaired source-only, dual-reviewed by fresh agents, and blindly
adjudicated on 25 disagreements. Five extraction errors remained nonterminal;
one final repair and fresh dual review closed all five. This changed six former
included decisions to exclusions. No task was selected by a downstream outcome.

## Terminal result

All 2,165 task units are terminal:

| Disposition | Count |
| --- | ---: |
| `QUALITY_INCLUDED` | 720 |
| `QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION` | 1,284 |
| `QUALITY_EXCLUDED_SOURCE_DEFECT` | 161 |

All final contracts are `faithful`; all evidence bindings are `supported`;
`pending_quality_count=0`. The included set contains 381 Python tasks and 339
tasks across eight other languages. Technical readiness remains separate: 101
tasks are currently `TECHNICALLY_READY` under the existing mechanism, Oracle,
and runtime stack. No technically ready row retains a diagnostic blocker.

## Execution independence

Logical reviewer slots are deterministic assignment labels, not persistent
agent identities. Repair producers, dual reviewers, and third adjudicators were
spawned as separate agent tasks in every repair round. The final two rounds used
`v6_repair_producer_*`, `v6_independent_reviewer_*`,
`v6_blind_adjudicator_*`, `v7_repair_producer`, and
`v7_independent_reviewer_*`. Thus no producer reviewed its own proposal. This
execution mapping is provenance for the completed local run; future released
bundles should include an equivalent machine-readable execution receipt.

## Reproduction coordinates

- base bundle: `.codex-runtime/subagent-full-review/inputs/base`
- final proposals: `.codex-runtime/subagent-full-review/proposals-4acfb5c-v7`
- terminal reviews: `.codex-runtime/subagent-full-review/reviews-4acfb5c-v7-terminal`
- reservation: `.codex-runtime/subagent-full-review/reservation-363991e-v4`
- final build A: `.codex-runtime/subagent-full-review/final-data-v7-a`
- final build B: `.codex-runtime/subagent-full-review/final-data-v7-b`
- canonical tracked release:
  `data/dataset-curation/reviewer-task-unit-dataset-v5`
- common bundle SHA-256:
  `33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`
- verifier status:
  `VERIFIED_DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED`

Both final builds and the tracked release contain the same ten files byte for
byte. The tracked release independently verifies as
`VERIFIED_DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED` and is the sole
reviewer-facing data coordinate. The reviewer
backend does not provide seed-stable replay, so future calls need not reproduce
the same prose. The frozen packets, decisions, assignment plans, prompts,
repairs, merge records, and final bundles are the reproducible artifact.
The local A/B run directories remain intentionally Git-ignored execution
provenance; the Git-tracked canonical copy closes the release-archive gap.
