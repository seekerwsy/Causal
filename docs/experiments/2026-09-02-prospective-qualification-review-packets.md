# Prospective qualification source-review packets

## Outcome

The latest v5 source population can now be handed to an independent reviewer
without exposing extractor outputs. Two exact candidate reservations were
prepared:

| Candidate role | Task units | Existing source-only realization strata | Unbound catalog-CWE challenges |
| --- | ---: | ---: | ---: |
| `QUAL_DEV` | 28 | 12 | 16 |
| `QUAL_ACCEPT` | 28 | 16 | 12 |

The 56 task units and their near-duplicate groups are mutually disjoint. Every
`QUAL_ACCEPT` candidate has empty method-exposure history. The selection used
no arm, generated code, Oracle result, discovery result, confirmation result,
or experimental outcome.

This is not a formal role assignment and does not open the one-shot acceptance
set. The bundle report therefore records:

```text
formal_role_assignment_frozen=false
independent_gold_complete=false
qualification_accept_attempts_authorized=0
provider_calls_authorized=0
```

## Frozen identities

- source data manifest:
  `33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`;
- producer commit:
  `2d66fccb4f29946f9ed0b94b4dcf53bba853d92f`;
- candidate bundle:
  `data/method/qwen37flash-qualification-source-review-candidates-v1`;
- candidate bundle manifest SHA-256:
  `1912f9c5cad5d43ddfdc44aff688c3eee62891184dc39aa6bb7e1a61ab4860ff`;
- `QUAL_DEV` task artifact SHA-256:
  `849c4a9731c4cb9575a2e9188aca582f80d455b9f6f813fffc7193f0f52a353a`;
- `QUAL_ACCEPT` task artifact SHA-256:
  `81ed85317291d585a2ff67383c045e7e6c2ada013613099339caeb817b786707`.

The candidate bundle was generated twice from the same inputs. All ten files
were byte-identical. The independent bundle verifier accepted the tracked
copy.

## Reproduction

From the repository root:

```text
.venv\Scripts\python.exe -m prompt_mechanism_study.cli representation prepare-qualification-review data/dataset-curation/reviewer-task-unit-dataset-v5 data/method/prompt-tsg-catalog-v1.json data/method/phase-context-policy-v3-mechanism-registry-v1.json OUTPUT --producer-commit 2d66fccb4f29946f9ed0b94b4dcf53bba853d92f --ranking-salt phase-context-policy-v3-qwen37flash-qualification-review-v1
```

The selection first reserves one unexposed candidate per source-only bound
catalog realization for `QUAL_ACCEPT`, then a second example for `QUAL_DEV`
where one exists. It fills the remaining fixed slots from unbound tasks whose
CWE maps to exactly one catalog family, balancing CWE and source lineage with
salted SHA-256 tie-breaks. Existing binding metadata is used only for selection
stratification and is omitted from the reviewer packets.

## Source-only review boundary

The independent reviewer may use only the exact prompt, source reference, and
finite catalog semantics, relations, guidance, and candidate realization IDs
inside each review packet. They must not read the selection audit, prior
binding/readiness labels, model responses, Prompt TSGs, generated code, arms,
Oracle/Judge results, or outcomes. The gold templates remain deliberately
invalid until every case is independently labelled and independence is
attested.

Preparing the packets exposed one generic implementation defect before any
acceptance run: the strict response-schema builder rejected a valid query scope
with zero required relation edges. The common builder now permits an empty,
closed `relation_decisions` object while still requiring every semantic key and
rejecting additional relation keys. Existing relation-bearing v4 requests are
byte-semantically unchanged.

## Gate at packet preparation

At packet preparation time, independent review of both source-only gold files
was still missing. Separately, author-approved scientific parameters and
power-qualified counts still had to determine all four prospective roles. Only
then could one complete five-role `DataRoleManifest` and one integrated
qualification plan be frozen. No `QUAL_ACCEPT` provider call is allowed before
those remaining conditions close.

The subsequent final-v5 capacity reconciliation is recorded in
the current [source-capacity contract](../research-dataset-spec.md). The power
figures in this dated development note used the superseded Gaussian approximation.
They do not qualify the repaired task-level analysis. Under the current 21-CWE
scope, 155 source-curated units remain after these two candidate reservations.
This is an upper bound before candidate-specific eligibility and disjoint
Discovery/Confirmation allocation. Sufficiency and any acquisition requirement
remain unknown until the repaired power and coverage gates close; this candidate
bundle alone does not make the study population-ready.

## Independent subagent review closure

The author subsequently approved an isolated agent-review interpretation of
the independence requirement. Two fresh Codex collaboration subagents, started
without prior turns, independently labelled all 56 source-only cases. They
agreed on 52 task-context coordinates. A third fresh subagent received only the
four disagreeing source cases, without either prior decision, and supplied the
four terminal blind decisions. The root agent performed schema validation,
hashing, and deterministic merge only; it made no semantic decision.

The tracked closure is
`data/method/qwen37flash-qualification-source-gold-v1`, with manifest SHA-256
`4854c62c2651001e144b79d547cdac489e9b84d2e84a53ffe277cec19bc5579f`.
It archives both complete reviews, the source-only third-review packet, the
third decisions, qualification-ready gold, and an execution receipt. The
receipt truthfully records `human_external_review=false`: this is independent
blind subagent gold, not external human-expert gold. No provider call, arm,
Oracle/Judge result, or experimental outcome entered the review.

This closes the independent source-gold gate only. The candidate reservations
remain non-formal, `QUAL_ACCEPT` remains unopened, and the five-role manifest is
still blocked by the power/capacity decision described above.
