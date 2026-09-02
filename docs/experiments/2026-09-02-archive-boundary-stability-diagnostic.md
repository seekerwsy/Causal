# Archive-boundary stability diagnostic — 2026-09-02

## Outcome

The prospectively frozen 24-call diagnostic stopped after its first eight calls
and is closed as `FAILED_CLOSED_INCOMPLETE_EXECUTION`. All eight provider calls
returned model response bytes, but the positive anchor failed deterministic
contract validation. The second and third replicates were therefore not started.

This result does not establish whether the archive boundary is stable. It does
identify a narrower upstream interface defect that must be resolved before that
question can be tested: both roles emitted an attribute outside the frozen catalog,
while the task-specific JSON Schema constrained only the attribute type and not
the finite allowed vocabulary.

## Frozen design and execution

The design reused one original archive prompt and three contrast prompts:

- original ambiguous archive origin;
- explicitly external and untrusted archive members (positive anchor);
- explicitly external but trusted archive members;
- explicitly internal and trusted archive members (negative anchor).

Each of proposer and reviewer was to annotate every variant in three sequential
replicates under `qwen3.7-flash-2026-07-15`, temperature 0, top-p 1, fixed seeds,
thinking disabled, one worker, and no retry. The frozen first decision rule required
any replicate that failed to close four contracts from eight calls to terminate the
experiment as incomplete.

Replicate 1 made exactly eight calls. It closed three contracts and rejected the
explicit-external-untrusted task during post-provider deterministic validation.
Replicates 2 and 3 were not opened, as required by the fail-stop rule.

## Exact failure attribution

The request supplied only these allowed attributes:
`caller_controlled`, `fixed`, and `security_sensitive`. For the positive anchor,
both proposer and reviewer classified `source.untrusted_archive_member` as
`present`, but each returned the attributes `caller_controlled` and `untrusted`.
The latter is not an attribute in the catalog, so the contract validator rejected
the task with `task context semantic attributes are invalid`.

The observed boundary is therefore:

1. provider transport and credentials succeeded for all eight calls;
2. all eight model responses were returned as parseable structured JSON;
3. both roles violated the supplied finite attribute vocabulary in the same way;
4. the generated strict response Schema allowed arbitrary strings in the attribute
   array, leaving the finite-vocabulary constraint to post-response validation;
5. the fail-closed validator correctly prevented an invalid contract from entering
   Prompt TSG output.

This supports a joint `MODEL_CONTRACT_ADHERENCE_AND_RESPONSE_SCHEMA_INTERFACE_GAP`
attribution. It does not support an attribution to transport, credentials, FCI, RD,
randomization, measurement, or ITT, none of which was exercised here.

## Partial observations and claim boundary

In the single incomplete replicate, both roles returned target-semantic states of:

| Variant | Proposer | Reviewer |
|---|---|---|
| Original ambiguous | present | present |
| Explicit external untrusted | present | present |
| Explicit external trusted | absent | absent |
| Explicit internal trusted | absent | absent |

These eight raw states are retained to diagnose the failure, but they provide only
two rather than the frozen six observations per variant. They cannot be used to
claim test-retest stability, choose between ontology readings, change source gold,
or qualify the extractor.

## Budget and reproducibility

The execution used 8 provider calls and conservatively charges CNY `0.039328`,
against maxima of 24 calls and CNY `0.117984`. Cumulative conservative
preexperiment spend is now CNY `1.420724`, leaving at least CNY `98.579276` under
the approved CNY 100 ceiling. No `QUAL_ACCEPT` calls were consumed.

The frozen plan is
`data/method/archive-boundary-stability-diagnostic-v1-plan.json`. The machine
result is `data/method/archive-boundary-stability-diagnostic-v1-result.json`, and
the closed raw bundle is archived under
`data/method/archive-boundary-stability-diagnostic-v1-evidence` with manifest
SHA-256 `e1a0647300eb6c37996e09b5de65bdd10c15a973b34c19eff409b266b10730e9`.
