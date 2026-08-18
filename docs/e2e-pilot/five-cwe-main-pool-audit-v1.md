# Five-CWE Main-Pool Outcome-Blind Audit

## Purpose

This stage freezes eligibility and finite functional contracts before code generation for the
five-CWE main experiment. It reads only the authenticated CyberSecEval v2 source audit, frozen split
simulation, original Prompt, target CWE, and bounded Oracle-profile semantics. Generated code,
intervention arms, generator identity, Oracle labels, and outcomes are absent from every request.

Each candidate receives one structured LLM audit proposal. Code then recomputes eligibility,
validates the response schema, and requires every functional evidence quote to be a verbatim
substring of the original Prompt. The selected task bundle will receive an explicit Codex review
before it is frozen. This replaces redundant duplicate pre-treatment judgments; the runtime
functional judge remains a separate one-pass, arm-blind evaluation of generated code.

## Zero-call preflight

The immutable input bundle is
`data/e2e-pilot/five-cwe-main-pool-preflight-20260818-01`. It contains 177 independent,
candidate-neutral Python packets and made zero provider calls.

| CWE | Discover candidates | Confirm candidates | Main quota |
| --- | ---: | ---: | ---: |
| CWE-78 | 30 | 30 | 8 + 12 |
| CWE-89 | 18 | 15 | 8 + 12 |
| CWE-502 | 16 | 15 | 8 + 12 |
| CWE-328 | 13 | 13 | 8 + 12 |
| CWE-338 | 14 | 13 | 8 + 12 |

The source audit SHA-256 is
`ff6b1118595a66d3a39f18c82a839441eb078313bd96220a36b24fd95205cd82`; the split-simulation
SHA-256 is `08ad0da161daf4180e9cc02606b55058b60856d2e02c7e077d7695c3d8a00391`; and the packet-bundle
SHA-256 is `62fb4f160d517ba1521025bc7d947ce2e08a508a73705850b9b3cca8fa985aeb`.

The earlier scope note listed 62 CWE-78 Python prompts. Re-execution against the authenticated
stage-0 audit found 60 records satisfying the actual pre-generation filters. The first preflight
therefore stopped before creating an output directory or making a provider call. The frozen config
now records 60; all five strata still exceed the registered discover and confirm quotas.

## Execution sequence

1. Run one candidate per CWE as a five-call Bailian canary.
2. Inspect schema validity, verbatim evidence, eligibility logic, and profile-specific rationale.
3. Audit all 177 candidates once using the same frozen policy.
4. Select the lowest preassigned rank keys that satisfy 8 discover and 12 confirm tasks per CWE.
5. Review the resulting 100-task bundle without generated outcomes, then freeze prompts and
   functional contracts before any main-model generation.
