# Source contract preparation

This is optional, outcome-blind preparation for new source data. Reviewers start
with the released frozen bundle and use:

```text
prompt-mechanism-study curate finalize task-units verify BUNDLE
```

Source preparation does not add a scientific stage or change task identities,
original prompts, deduplication, formal roles, generated code or outcomes. The
[dataset specification](research-dataset-spec.md) identifies the released inputs,
protected reservations, completed source reviews and their limits.

## One preparation path

```text
source-backed proposals → independent review → repair rejected/nonterminal items
→ review changed items → assemble and independently verify the task-unit bundle
```

`curate prepare content` is the single producer entry for an existing task-unit
bundle. It runs these steps internally:

1. For contracts already judged faithful, bind evidence without changing their
   semantic fields. A failed binding goes to repair, not source exclusion.
2. Repair faulty or unbound contracts from the original source, one task per
   request. The repair prompt returns contract content only.
3. Bind evidence to those fixed repaired contracts, one task per request.
4. If exact localization still fails, retain the full original prompt as evidence
   with `full_prompt_pending_review`. This locates the proposal; it does not
   certify semantic support or source sufficiency.

Every proposal then receives the existing independent source review. There are
no separate producer-side adjudication, correction and evidence-materialization
commands. Remaining semantic disagreements belong to that review and its existing
repair path. Raw responses, unsuccessful localization and all task identities
remain recorded. A malformed response remains a recorded error, not a missing task.

For already restored upstream inputs, `curate prepare restored-contracts` builds
source-backed proposals with the source-use bundle and reservation firewall. It
enters the same independent review and finalization path; restoration cannot
inherit the old prompt's qualification.

## Evidence and judgment boundaries

Evidence retains the exact source identity and UTF-8 byte span: prompt hash,
start/end byte, quoted text and span hash. The prompt hash is the canonical JSON
string content hash. Response-format instructions are not software behavior.
Unrelated missing details do not make a source universally unusable; candidate
sufficiency and measurement scope are assessed separately.

Producer judgments are diagnostics. Independent review receives the source,
proposed contract and evidence, without outcomes, arms, generated code, readiness
or producer sufficiency judgments. Two blind decisions and, on disagreement, a
blind third decision determine the existing source-quality record. Repairs of
nonterminal items must be independently reviewed again. Exact spans or a valid
schema do not establish semantic correctness.

The finalizer still requires faithful, evidence-supported terminal review; it
cannot turn producer failure into source insufficiency. Unknown candidate facts
remain unknown. Existing role/exposure and near-duplicate boundaries are preserved,
and no formal Discovery or Confirmation role is assigned here.

## Commands for author preparation

Before reviewing new material, establish the prompt-blind reservation with
`curate prepare reservation BASE RESERVATION --producer-commit COMMIT`.
Then run one bounded producer pass:

```text
prompt-mechanism-study curate prepare content BASE PROPOSALS --producer-commit COMMIT --max-new-batches 1
```

The batch limit applies to each reached producer stage. Resume the same unchanged
plan to finish its remaining batches; completed batches are reused. Changed code,
prompts or inputs require a new output directory. Provider spending requires the
owner's authorization; the command itself grants none.

Each batch makes one provider attempt. Provider or response failures are saved
as errors by the common batch executor; there is no additional automatic retry
inside contract preparation. Successful saved batches remain reusable under the
same frozen plan.

The complete proposals are in `PROPOSALS/final`. Use the existing review commands:

```text
prompt-mechanism-study curate review prepare BASE PROPOSALS/final REVIEW-PACKETS --producer-commit COMMIT
prompt-mechanism-study curate review seal REVIEW-PACKETS DECISIONS INITIAL-REVIEW
prompt-mechanism-study curate review finalize INITIAL-REVIEW ADJUDICATION-DECISIONS PROPOSALS/final REVIEW-ROUND
```

The review and adjudication decisions must first be supplied independently from
the frozen packets; these commands do not manufacture model judgments.
`curate review verify` replays the saved review. For nonterminal items,
`curate repair prepare` and `curate repair finalize` consume explicit repair
packets/decisions; review the changed proposals and merge the resulting review
with `curate review merge`. Each command's `--help` gives its exact arguments.

Finally, use the latest proposals and terminal reviews:

```text
prompt-mechanism-study curate finalize task-units build FINAL --base-bundle BASE --proposals-root LATEST_PROPOSALS --reviews-root FINAL_REVIEWS --reservation-root RESERVATION --producer-commit COMMIT
prompt-mechanism-study curate finalize task-units verify FINAL
```

Task-unit, source-provenance, evidence, quality and reservation verification remain
unchanged. Terminal source quality is not formal experiment admission or proof of
complete functionality. Completed historical cohorts keep their original rules.

## Historical execution

The former split semantic/evidence repair commands, repeated evidence dispute
steps, standalone proposal assembler and unused single-provider review are
preserved on local branch `codex/pre-artifact-scope-20260923` at `f1cd0011`.
The branch also preserves this document's old execution sequence. Reproduce old frozen runs with
their corresponding implementation; current code must not overwrite or reinterpret
them. This consolidation does not change FCI, experimental arms or inference.
