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

The next permissible provider gate is not a randomized experiment. It is to freeze
role-disjoint prospective `QUAL_DEV` and one-shot fresh `QUAL_ACCEPT` manifests,
seal profile v4 and all thresholds before opening `QUAL_ACCEPT`, and qualify the
remaining Flash roles. Until then, the repository remains `SPECIFIED_DRAFT` and
formal provider execution remains disabled.
