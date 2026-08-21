# Functional Judge v2b remediation checkpoint

## Scope and claim boundary

This checkpoint records a development-only calibration repair. It does not replace the frozen
Security Oracle, does not change any generated program, and does not authorize a scientific or
formal claim. `Y_F^J` remains the scalable AST-gated, single-shot LLM guardrail; `Y_F^E` remains a
separate executable-functional sidecar.

## Immutable failed v2 attempt

- Deployed commit: `84d6dc265b75dab257c42739334faa5634d5a66b`.
- Deployment: `/home/ubuntu/secaware-deployments/functional-judge-calibration-84d6dc2-20260821-06`.
- Deployment manifest: `db32ae946a06e3197ee878a8028696ac91180eae1fa700a9ffa6ce40c4716979`.
- Execution root: `/home/ubuntu/secaware-experiments/executions/functional-judge-calibration-84d6dc2-20260821-06`.
- Execution manifest: `b10da690961070a968b9a1b5fee83d36a8c1da9c9787e064127fb088dd7b2734`.
- Local failure handoff: `runs/functional-judge-calibration/attempt-84d6dc2-20260821-06/final-delivery.json`.
- Old v2 prompt SHA-256: `dffe6d72f957182946a9195a7d46b0e10a510ed484fa9f191c3908719db1d54e`.
- Old v2 evaluator-config SHA-256: `a44c1891eabd27f5c03593f673ab8bc0ef0996726584381d6783b974833fc2fe`.

The old prompt and config are preserved as non-active evidence snapshots under
`data/functional-judge/blind-calibration-v3/history/qwen35flash-prompt-v2/`. The attempt completed
24/24 baseline v1 measurements. The v2 pilot received two provider responses, produced one partial
outcome, and then stopped with `API_INVALID_RESPONSE`; v2 remaining and the analyzer were never
started. The total closed-trace count was 26, with zero generation calls and zero Security Oracle
executions.

The second v2 response correctly identified the GTF/FASTA append failure but populated a non-null
`behavior_trace` for two `not_met` verdicts. The visible JSON schema allowed that representation,
while the local parser required null, so the root correctly remained `ERROR`. Independently, the
first v2 response falsely passed the PDF program by assuming that `pdftotext INPUT.pdf` emits its
result on stdout. The old error root remains immutable and is not normalized or resumed.

## Tune-informed v2b candidate

The v2b candidate keeps the same `qwen3.5-flash-2026-02-23` model, seed, sampling parameters,
single-pass mode, output parser, gold labels, and calibration thresholds. It changes only the
candidate identity and system prompt:

- Candidate ID: `qwen35flash-prompt-v2b`.
- Active config: `data/functional-judge/blind-calibration-v3/evaluator-qwen35flash-v2b.json`.
- Config SHA-256: `263a59443d602bc12ede47fc585dd969b4c1d60aab594aced7a1e250878fe43b`.
- Active prompt: `src/secaware/functional_judge/prompts/functional_judge_v2.txt`.
- Prompt SHA-256: `980427722b1fda988b25423987d722264aa5c74fa76ed015872ccda21fbb4bc5`.

The prompt adds two classes of guidance: an exact per-verdict field matrix with a canonical
`not_met` JSON example, and general external-interface checks covering stdout versus file output,
redirection, SQL grammar positions, scheduler accounting, and observable file formats. These
changes were derived only from the eight exposed tune cases and the failed v2 pilot:

- Executable sidecar manifest: `4d362def0a380c637c533a42decc8bfa6cdc98065edb8e7c0a1d699a539822e9`.
- Eight-row tune authority: `/home/ubuntu/secaware-experiments/summaries/executable-functional-sensitivity-6af285a-20260821-04/judge-tune-cases.jsonl`.
- Tune authority SHA-256: `b36b52bccd6f1eafd4f11321f234e230186fe3c3b3bd943333fb62b9e7489dac`.

The v2b prompt did not use validation fixture programs, per-case outcomes, case IDs, or labels. The
validation file is bound by SHA-256
`8e62c17753dd09c352a89571429aec5ecd4dc2b41280cdaeb8d3835fa9a8dca6`. The failed handoff exposed
only baseline aggregate counts; those counts identify no program or case and did not determine any
prompt rule. The candidate patch and hash above were fixed before any v2b validation execution.
Therefore v2b is a same-family, tune-informed candidate, not a general-correctness claim.

## Next executable gate

The next run must use a new commit, immutable deployment, plan, four zero-call preflights, campaign
receipt, and fresh candidate/output roots. It must retain the frozen four-phase order and the
2/22/2/22 closed-trace budget. The v2b pilot may proceed to remaining only if both pilot cases close
normally, produce two traces and two outcomes, contain zero invalid responses, and classify both
the PDF and GTF/FASTA cases as `FAIL`.

The schema/parser mismatch remains a known P1. If v2b again emits a semantically valid `not_met`
trace that violates the current null rule, the run must stop without retry. The next repair would be
a distinctly versioned parser/schema policy that accepts and canonically normalizes bounded
`not_met` traces while retaining raw response bytes. Replacing the Judge model is deferred until a
schema-aligned candidate has been measured and still fails the frozen validation gate.
