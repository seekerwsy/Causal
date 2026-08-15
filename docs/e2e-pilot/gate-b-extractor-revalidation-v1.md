# Gate B Extractor Revalidation v1

## Purpose

This bounded stage re-extracts the complete two-source/eight-variant Gate B Prompt set with the
admitted production facts extractor. It reuses six immutable valid intervention responses from
`gate-b-v4-resume-live-20260815-02` and the two separately repaired placebo responses. It does not
repeat a valid intervention and does not generate code or outcomes.

## Inputs and provenance

The two selected tasks, four arms per task, AllowedDelta contracts, and assignments originate from
the passed Gate A artifacts. Every frozen intervention request and response must form one complete
pair, cover exactly one selected Gate A variant, preserve the exact source Prompt prefix, and match
the Gate A arm, operation, task, and source digest. The failed prior Gate B attempt must be preserved
and must identify `TARGET_VARIATION_VIOLATION` as its terminal failure.

The new extractor policy, system template, FeatureSpec catalog, criteria-projection version, Prompt
text, request bytes, response bytes, proposal, typed graph, and validation result are independently
recorded. Old extractor responses are not reusable because their request bytes and policy digest do
not match the admitted extractor.

Both repaired placebo suffixes must pass
`unicode-chars-relative-10pct-min5-v1`: non-empty, distinct from no-op, and within
`max(5, ceil(0.10 * target_length))` Unicode characters of the corresponding target suffix. The
combined block must also produce ten distinct extractor request byte sequences.

## Execution boundary

Plan mode creates and audits all ten exact extractor requests with zero provider calls. Live mode,
when separately approved, sends exactly those two source and eight variant requests to the configured
facts extractor. There is one attempt per Prompt and no semantic retry. The six valid historical
interventions and two admitted placebo repairs are not repeated.

Every variant is evaluated with the existing Gate B AllowedDelta, target-state, sentinel, and task-
projection-drift logic. Task-layer drift remains diagnostic; target-state, non-task AllowedDelta, and
sentinel violations remain hard failures. The runner collects all ten extraction outcomes and all
eight validation outcomes instead of stopping after the first failed variant.

## Gate

The stage passes only when all ten Prompts extract successfully and all eight variants pass the
existing Gate B validation. Passing authorizes consideration of the next bounded code-generation
canary; it is not a scientific performance claim and does not itself authorize provider-based code
generation.
