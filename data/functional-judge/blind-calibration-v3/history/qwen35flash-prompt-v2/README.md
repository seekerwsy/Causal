# Historical qwen35flash prompt-v2 snapshot

This directory preserves the evaluator configuration and system prompt used by the immutable
`84d6dc2` calibration attempt. These files are evidence snapshots, not active evaluator inputs.
The active tune-informed replacement is `evaluator-qwen35flash-v2b.json` in the calibration root;
its system prompt is loaded from `src/secaware/functional_judge/prompts/functional_judge_v2.txt`.

The old attempt stopped after two v2 pilot responses because the second response violated the
frozen cross-field output contract. It must not be resumed, overwritten, or reinterpreted as a
completed calibration.
