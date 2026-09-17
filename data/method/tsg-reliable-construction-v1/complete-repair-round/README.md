# Complete bounded TSG repair round

Two exposed tasks, nine fresh Codex steps, zero external API calls. No formal
qualification, protected task exposure, generated-code measurement or paper change.

Read `protocol/plan.json`, `analysis/summary.json`, then `analysis/source-audit.json`.
The exact frozen source is recorded in the plan. Reviewer inputs are masked:
case-01 privilege control, case-02 registration wrong target, case-03 privilege
wrong target, case-04 registration control. No reviewer saw those labels.

Both planted target errors were repaired in one patch; correct actors and owned
order remained. One control was unchanged; the other preserved the target policy
but contracted username role/participation into uncertainty. These are targeted
author judgments, not whole-graph certification. Two actual deleted-source drafts
compiled and omitted their target instructions. Both active whole-policy REMOVE
attempts still failed non-target preservation; no natural edit was qualified.

`completed-execution/result.json` contains the actual frozen review/patch path's
final records, contracts and graphs, plus both edit failures. `execution/result.json`
retains the first harness attempt: order-only differences in JSON Schema `required`
and `enum` arrays triggered assertions. The completed replay compares those arrays
by schema meaning, keeps exact request-object comparisons, and uses the same model
responses without resampling. This is not a semantic model failure.

The current review-input correction passes compiler-expanded impacts to the existing
reviewer. It was implemented and tested after these outputs; the retained model
results must not be credited to that correction. The broad ownership/applicability
limitation remains explicit rather than bypassing the editor.

From repository root, run the existing offline verifier:

```text
.venv/Scripts/python.exe data/method/tsg-reliable-construction-v1/verify.py
```

This replays retained responses, compilation, merge restrictions and edit failures,
checks byte identities, and recounts author judgments. It does not resample models
or independently prove the semantic judgments. The current implementation check
is retained in `analysis/implementation-check.json`.
