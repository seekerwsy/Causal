# Five-CWE Main-Prompt Gate C Canary v1

## Purpose

This stage carries the five passed Gate B Prompt blocks into separate Qwen2.5-Coder-7B and
Phi-4-14B outcome-pipeline canaries. It is an engineering validation with one task per CWE, not a
powered effect estimate. Code generation remains pilot-first and each model is analyzed as a
separate stratum.

## Frozen inputs

- Prompt tasks and one-pass functional contracts:
  `data/e2e-pilot/five-cwe-main-prompt-canary-inputs-20260818-09`.
- Qwen assignment stratum:
  `data/e2e-pilot/five-cwe-main-prompt-canary-gate-a-20260818-10`.
- Phi assignment stratum:
  `data/e2e-pilot/five-cwe-main-prompt-canary-gate-a-phi4-14b-20260818-11`.
- Model-independent LLM Prompt variants:
  `data/e2e-pilot/five-cwe-main-prompt-canary-gate-b-control-blind-20260818-03`.

The Qwen and Phi Gate A `variants.jsonl` and `candidates.jsonl` files have identical SHA-256
digests. Their assignment ledgers differ by registered model stratum, as required.

## Append-suffix provenance adapter

The historical direct Gate B adapter authenticated raw responses containing a complete
`candidate_text`. The current Gate B stores only `append_suffix`. The updated adapter accepts both
explicit envelopes. For the suffix envelope it requires the mode to agree in the variant and raw
request, requires the raw response to contain exactly the single suffix key, rejects empty or
source-repeating suffixes, reconstructs `source_prompt + append_suffix`, and then applies the
existing Prompt hash and closed-manifest checks.

## Execution order

1. Build both zero-provider Gate C plans and validate all 20 assignments per model.
2. Observe GPU, service port, network, and Oracle-tool readiness.
3. Start Qwen 7B, run one pilot unit, inspect the complete generation/Judge/Oracle trace, then run
   the remaining 19 only after an explicit saved authorization delta.
4. Stop Qwen, restore GPU readiness, and repeat for Phi 14B.
5. Preserve every run directory and download closed artifacts before any scale-up decision.

## Error log

- The first local targeted-test command reached collection but did not run tests because a new
  parametrized test used `request`, a name reserved by pytest. No provider call, experiment output,
  or external process was involved. The parameter was renamed to `request_payload`; the complete
  targeted set must be rerun before planning.
- A read-only PowerShell command intended to summarize artifact directory sizes had an invalid
  pipeline placement and stopped at parse time. It created or changed no file. The corrected command
  reported 181 frozen files across the two plans, two preflights, Phi Gate A, and Gate B bundle;
  133 of those files belong to the downloaded Gate B bundle.
