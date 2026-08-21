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

## Canary v1 diagnostic

The first five-call canary reached Bailian for all five candidates but normalized zero decisions.
All five responses failed the local response model because it unnecessarily required alphabetic
requirement/dependency order and one fixed priority among multiple valid rejection reasons. The
run is preserved at
`/home/ubuntu/secaware-experiments/main-pool-audit/five-cwe-main-pool-canary-bailian-20260818-01`.
It generated no code and observed no outcomes.

The v2 parser retains the substantive gates—eligibility is recomputed, evidence must be verbatim,
and the finite-profile booleans must support the decision—but accepts semantically equivalent field
orders and any rejection reason backed by a failed eligibility condition. It also records every raw
provider response before normalization and retains bounded validation details for invalid responses.

## Evidence-bound semantic canary

After two preserved schema/semantic diagnostics, the final request policy supplied deterministic
source-Prompt segments and prohibited target-security mechanisms from entering functional criteria.
Five previously reviewed positive tasks—one per CWE—were evaluated. Their raw responses all judged
the task eligible. Three normalized directly; two returned unique substrings of registered evidence
segments. The final parser expands only a unique exact substring to its containing registered
segment. Offline replay recovered all five with zero additional provider calls and expansion counts
of 4, 0, 0, 3, and 0.

The source run is
`/home/ubuntu/secaware-experiments/main-pool-audit/five-cwe-main-pool-known-positive-bailian-v5-20260818-05`.
The five record IDs are 1658, 1603, 1642, 1638, and 1580. Their criteria describe only requested
task behavior; the generated-code safety mechanisms remain outside the functional contract.

## Full candidate audit

The full run is
`/home/ubuntu/secaware-experiments/main-pool-audit/five-cwe-main-pool-full-bailian-v1-20260818-07`.
It audited the remaining 172 candidates serially. Every unit was flushed immediately. Provider calls
completed for 172/172 candidates with no authentication, network, or provider failure: 165 responses
normalized directly and seven retained raw responses for offline repair.

Before the seven repairs, the full run accepted 71 candidates. Adding the five excluded known-positive
canary tasks gives the following outcome-blind eligibility counts:

| CWE | Direct full-run eligible | Known-positive reuse | Current total |
| --- | ---: | ---: | ---: |
| CWE-78 | 33 | 1 | 34 |
| CWE-89 | 13 | 1 | 14 |
| CWE-502 | 6 | 1 | 7 |
| CWE-328 | 15 | 1 | 16 |
| CWE-338 | 4 | 1 | 5 |

These counts are pre-generation diagnostics, not outcome results. They show that the registered
8-discover/12-confirm quota per CWE cannot be filled from CyberSecEval v2 without admitting tasks
that lack the target operation. The main pool must therefore either add authenticated neutral tasks
from other datasets or preregister unequal/secondary strata before any main-model generation. It
must not backfill tasks based on generated outcomes.

The repository archive at
`data/e2e-pilot/main-pool-audit-through-full-20260818-07` preserves all six diagnostic/canary/full
runs. Its transfer archive SHA-256 is
`0450eb36c3b92e06cbd6ddef618edde76260f6d2c5b6e7f5ffd5732897fc3847`.

## Outcome-blind reconciliation

The offline reconciliation at
`data/e2e-pilot/five-cwe-main-pool-reconciliation-reviewed-20260818-02` verifies the retained
response-bundle hashes, replays the final parser, and combines the known-positive and full runs.
Seven malformed responses received explicit Codex-primary overrides recorded in
`configs/e2e-pilot/five-cwe-main-pool-audit-overrides-v1.jsonl`. The review used only each source
Prompt, its registered evidence segments, target CWE, finite profile, and retained audit response;
generated code, intervention arms, generator identity, Oracle results, and outcomes remained
unavailable.

The reconciliation produced 177/177 decisions, zero unresolved records, and zero provider calls.
The reviewed eligible pool is:

| CWE | Discover | Confirm | Total |
| --- | ---: | ---: | ---: |
| CWE-78 | 19 | 18 | 37 |
| CWE-89 | 9 | 6 | 15 |
| CWE-502 | 5 | 2 | 7 |
| CWE-328 | 10 | 7 | 17 |
| CWE-338 | 2 | 3 | 5 |

This resolves response-format uncertainty but does not solve source coverage. CWE-502 and CWE-338
remain far below the registered split quotas, while CWE-89 and CWE-328 lack enough confirm tasks.
Cross-source supplementation must therefore be assessed before freezing the main experimental pool.
