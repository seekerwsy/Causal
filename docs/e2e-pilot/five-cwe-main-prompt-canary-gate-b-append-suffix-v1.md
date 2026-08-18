# Five-CWE Main Prompt Canary: Gate B Append-Suffix Executor

## Scope

This note records the first live Gate B failure and the bounded interface change used for the
next run. It does not contain generated-code outcomes and does not authorize Gate C.

## Preserved failed run

- Host: target GPU server reached through the registered jump host.
- Run directory:
  `/home/ubuntu/secaware-experiments/runs/five-cwe-main-prompt-canary-gate-b-20260818-01`
- Status: `GATE_B_FAILED`.
- Completed before failure: 5 source Prompt extractions.
- Failed operation: the first intervention call, a CWE-502 `TARGET_PATCH` variant.
- Failure code: `SOURCE_PREFIX_VIOLATION`.
- Cause: the LLM returned a complete candidate and edited text inside the original Prompt even
  though the system instruction required the original Prompt to remain an exact prefix.
- Interpretation: intervention-executor interface failure, not an extractor result and not an
  outcome result.

The failed run is immutable and must not be reused as the output directory of a later attempt.

The first `append_suffix_v1` live attempt is also preserved at
`/home/ubuntu/secaware-experiments/runs/five-cwe-main-prompt-canary-gate-b-append-suffix-20260818-02`.
Its first target arm passed exact-prefix and target-realization checks. Its following no-op arm
failed because the LLM appended a deserialization safety requirement, producing
`ALLOWED_DELTA_VIOLATION` and `TARGET_VARIATION_VIOLATION`. The no-op request had no allowed
transition, but it still exposed the registered target feature identifier; this is treated as
control-arm semantic priming rather than extractor failure.

## Frozen correction: `append_suffix_v1`

The LLM receives the source Prompt and bounded intervention contract but returns exactly one JSON
field, `append_suffix`. The orchestration layer validates that response and constructs the final
candidate as:

```text
candidate_prompt = source_prompt + append_suffix
```

This makes source preservation a structural invariant while retaining the LLM as the executor of
the natural-language intervention. The validator rejects empty or whitespace-only suffixes,
duplicate or additional JSON keys, oversized responses, and accidental repetition of the complete
source Prompt. Existing full-candidate execution remains available for prior configurations; only
the new five-CWE canary opts into `append_suffix_v1`.

For `append_suffix_v1`, the target feature and operation are exposed to the LLM only for the
`target_patch` arm. They are withheld from no-op, placebo, and generic control requests. Those
requests remain bound to their frozen candidate and variant identifiers in provenance, while the
LLM sees only the arm-specific `allowed_delta` and objective needed to execute the control. This
prevents the target label from prompting target semantics into a control suffix.

## Validation and rerun policy

1. Run the append-suffix parser, payload, placebo, randomized-canary, and main-canary tests.
2. Commit the change before deployment.
3. Deploy the committed archive to a new immutable server directory.
4. Execute Gate B in a new run directory; do not overwrite the preserved failure.
5. Permit Gate C only if all 20 variants pass source-prefix, allowed-delta, target/generic
   realization, and length-matched placebo checks.
