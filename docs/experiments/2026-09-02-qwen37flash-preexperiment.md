# Qwen3.7-Flash preexperiment entry — 2026-09-02

## Outcome

The approved CNY 100 non-confirmatory budget was used only for role-development and
qualification work with the fixed Beijing Bailian snapshot
`qwen3.7-flash-2026-07-15`. No formal role, formal Prompt TSG, discovery outcome,
randomized assignment, generated arm, or effect result was opened.

The exposed Functional Judge regression passed with 15/16 correct, one false pass,
and zero invalid responses. The final Prompt-contract profile (`response protocol
v4`, implementation `c1d3a0a`) met every unchanged legacy-exposed development
threshold:

- 27/28 exact task-context matches (`0.964286`, required `>= 0.90`);
- present recall `0.90` (required `>= 0.80`);
- false-positive-present count `0` (maximum `0`);
- wrong-realization count `0` (maximum `0`).

The raw qualification status string is `QUALIFIED_FOR_FORMAL_EXTRACTION`, but its
paper-facing interpretation is narrower: the input is legacy-exposed development
data, so this is profile-development evidence only. It does not authorize formal
use and does not replace a fresh, role-disjoint `QUAL_ACCEPT` run.

## What changed during development

The first provider-compatibility attempt failed before raw responses were archived.
The extractor was changed to write requests, raw responses, call counts, and errors
before fail-stop. Later closed failures identified transport mismatches rather than
changes to the Prompt-TSG hypothesis semantics:

1. the provider schema omitted the local rationale-length bound;
2. non-present rows sometimes carried irrelevant evidence payloads;
3. otherwise correct evidence was wrapped in quotation marks, double-escaped, or
   copied with different whitespace.

The active response protocol now bounds rationale strings, trims rationale boundary
whitespace, clears evidence fields for non-present rows, and maps only conservative
quote/escape/whitespace variants back to an exact source-Prompt span. If no exact
span can be reconstructed, the decision still becomes `UNRESOLVED`. Raw provider
responses remain unchanged in the evidence bundle and the independent qualifier
replays the same normalization.

No qualification threshold, gold label, consensus state rule, task selection, or
candidate realization was relaxed. One remaining expected-present JSONField case
stayed unresolved because proposer and reviewer genuinely disagreed; it remains in
the denominator.

## Cost closure

The conservative ledger counts 200 closed calls plus six calls reserved for the
pre-fix unclosed concurrent attempt:

- Functional Judge: 16 calls, CNY `0.039328`;
- Prompt-contract work: 184 closed calls plus six reserved calls, CNY `0.934040`;
- conservative total: CNY `0.973368`;
- minimum remaining from the approved cap: CNY `99.026632`.

No promotion, free quota, cache discount, fallback model, replication model, or
automatic retry is credited. `ALI_BAILIAN_API_KEY` was loaded only inside the
remote execution environment and neither its name-value pair nor secret material
appears in a result artifact.

## Evidence and next gate

The machine-readable attempt, hash, cost, and evidence-boundary record is
`data/method/qwen37flash-preexperiment-ledger-v1.json`. Its final extraction bundle
has manifest SHA-256
`f106936a260b1df6072ddd325342fdab002f5d40e8d28603c6edd1f7fbb6d495`;
the independent qualification bundle has manifest SHA-256
`0b629e70ba816a9567c1d94d263e7c58623adddcb0b6fc7801fcaa4ea50844c2`.

The raw bundles currently exist in the named remote experiment roots and in ignored
local `.codex-runtime` copies. They still require a tracked reviewer archive before
publication.

The next permissible provider gate is not a randomized experiment. Subsequent
same-date prospective `QUAL_DEV` work is recorded below; `QUAL_ACCEPT` and all
formal roles remain closed.

## Prospective source-only QUAL_DEV update

Two isolated model reviewers labelled all 56 source-only cases independently, and
a third isolated reviewer adjudicated only their four disagreements. The frozen
gold bundle has manifest SHA-256
`4854c62c2651001e144b79d547cdac489e9b84d2e84a53ffe277cec19bc5579f`.
This is independent model-review evidence, not external human gold. No root-agent
semantic label was added, and the 28 `QUAL_ACCEPT` labels were not opened during
provider execution.

The first full prospective `QUAL_DEV` candidate completed 56 model calls but
failed the unchanged gate:

- 17/28 exact task-context matches (`0.607143`);
- present recall 3/7 (`0.428571`);
- false-positive-present count `0`;
- wrong-realization count `0`.

Development then remained within `QUAL_DEV`. Candidate v2 failed closed after
three proposer calls because its stricter provider JSON Schema returned no model
response bytes. Candidate v3 restored the previously exercised schema and closed
all six targeted canary calls, but matched only one of three cases. The final
prompt-only candidate v4 added two general interface-composition rules and again
closed all six calls, but matched only the archive case; YAML and SQL remained
unresolved. Its exact accuracy and present recall were both `0.333333`, with zero
false positives and zero wrong realizations.

The v4 plan prospectively required prompt-only tuning to stop after this failure.
Accordingly, no 28-task v4 run, `QUAL_ACCEPT` call, role assignment, Prompt TSG
publication, Discovery run, or randomized experiment occurred. The representation
candidate was therefore not ready for formal use under the prompt-only path.

An explicit evidence-aware representation redesign then separated semantic
classification from evidence-span validity. A zero-network replay of the archived
v4 raw responses matched all three canary cases. Under the prospectively frozen v5
plan, six new calls were made on the same three source-only cases. The independent
replay matched YAML and SQL, but both fresh archive annotations classified the
required archive-confinement semantic and relation as absent. The v5 canary therefore
closed at 2/3 exact accuracy and `0.666667` present recall, with zero false-positive
present and zero wrong realization. This is evidence of cross-call semantic
classification instability, not a remaining evidence-field aggregation error.

The v5 failure rule stopped execution before the 28-task full run. No `QUAL_ACCEPT`
call, role assignment, Prompt TSG publication, Discovery run, randomized experiment,
or scientific effect claim occurred. The evidence-aware representation candidate is
**not ready** for formal use, and no automatic prompt or consensus iteration is
authorized.

A subsequent zero-network [error-attribution audit](2026-09-02-prompt-contract-error-attribution-audit.md)
recomputed the v1 raw-state failures and v3-v5 canary history. Among the 11 v1
mismatches, eight contain a proposer/reviewer semantic disagreement, three contain
shared abstention, four contain a unanimous-present evidence demotion, and one is a
unanimous semantic false negative; categories overlap. The audit localizes the current
v5 blocker to semantic test-retest instability at an under-specified ontology boundary,
not provider transport, evidence aggregation, or observed query/binding replay drift.
It consumed no provider calls and changed no qualification label or active method.

## Prospective cost and evidence closure

Prospective `QUAL_DEV` used 83 calls with a conservative cost of CNY `0.408028`.
Together with the earlier CNY `0.973368`, cumulative conservative preexperiment
spend is CNY `1.381396`; at least CNY `98.618604` remains under the approved CNY
100 preexperiment ceiling. No retry, fallback, free-tier credit, or cache discount
is counted, and `QUAL_ACCEPT` consumed zero calls.

All ten closed prospective extraction/qualification bundles are now tracked at
`data/method/qwen37flash-prospective-qual-dev-development-evidence-v1`. The exact
attempt and budget ledger is
`data/method/qwen37flash-prospective-qual-dev-execution-ledger-v1.json`. The
repository remains `SPECIFIED_DRAFT`, and formal provider execution remains
disabled.
