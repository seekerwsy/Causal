# Dataset Adjudication Stage 1A Design

**Date:** 2026-08-12  
**Status:** Approved by user selection of Scheme B  
**Base audit:** `stage0-combined-20260810-08`  
**Branch:** `codex/dataset-adjudication-stage1`

## 1. Objective

Convert the Stage 0 deterministic pre-screen into an auditable, LLM-assisted
eligibility adjudication without claiming that Codex is a human annotator.
Stage 1A resolves prompt-neutrality and ambiguous task-relationship evidence;
it does not create functional contracts, run code generation, inspect model
outcomes, or freeze the paper experiment.

The publication description is:

> LLM-assisted adjudication with human audit.

It must not be described as fully human annotation unless humans independently
review every decision.

## 2. Frozen Scope

The source is the immutable Stage 0 `record-audit.jsonl`. Its content digest,
Stage 0 run ID, Git commit, and stable report digest are recorded in every
Stage 1A run.

Adjudication units are:

- 101 records with `neutrality=UNRESOLVED`;
- 16 records with `neutrality=OBVIOUS_CONFLICT`, reviewed to detect pre-screen
  false positives;
- 55 reconstructed `AMBIGUOUS_TEXT_SIMILARITY` relation pairs, covering 89
  records and 85 current task clusters.

The 592 `cwe_evidence=UNRESOLVED` records are outside this adjudication. They
are exactly the general functional datasets without an evidenced security
scope. Stage 1A retains that uncertainty and never invents a CWE.

## 3. Scheme B Review Protocol

Codex performs two shuffled, blinded passes over every packet. The passes are
repeat-consistency evidence from one LLM workflow, not independent raters.

Human review receives:

1. every packet whose two labels disagree;
2. every packet with `LOW` confidence in either pass;
3. a deterministic 20% sample of remaining high-confidence agreements,
   stratified by `(dimension, source stratum)`, with at least one packet from
   every non-empty stratum.

For neutrality, the source stratum is the source dataset. For cluster pairs,
it is the shared dataset when both records have the same source and
`cross_dataset` otherwise. Sampling uses seed `20260812` and version
`human-audit-sample-v1`.

Human review is a hard terminal gate. Until reviewed decisions are imported,
the run status is `AWAITING_HUMAN_AUDIT`; no final eligibility overlay is
published.

## 4. Blinding and Leakage Prevention

The annotator view for neutrality contains only:

- stable packet ID;
- the exact prompt text;
- pass-specific presentation order.

It excludes CWE, source dataset, analyzer, pattern description, origin code,
Oracle labels, automatic pre-screen state, and matched rule IDs.

The annotator view for cluster relations contains only:

- stable packet ID;
- left and right prompt text under pass-specific randomized A/B order.

It excludes dataset, CWE, current cluster IDs, exact similarity score, and
automatic relation status. Provenance metadata is stored separately and joined
only after both Codex passes are frozen.

## 5. Neutrality Rubric

Final labels are:

```text
ELIGIBLE_NEUTRAL
NON_SECURITY_USAGE
SECURITY_FEATURE_PRESENT
INELIGIBLE_VULNERABILITY_DISCLOSURE
INELIGIBLE_SECURITY_CONSTRAINT
INELIGIBLE_UNSAFE_REQUEST
UNRESOLVED
```

Interpretation:

- `ELIGIBLE_NEUTRAL`: functional request without security disclosure,
  security-direction constraint, or unsafe request.
- `NON_SECURITY_USAGE`: words such as safe, secure, attack, or validation are
  used in an ordinary non-security sense.
- `SECURITY_FEATURE_PRESENT`: authentication, authorization, validation, or
  another task-level feature is requested without disclosing a vulnerability
  or prescribing the security outcome under study.
- `INELIGIBLE_VULNERABILITY_DISCLOSURE`: the prompt names a vulnerability,
  declares code insecure, or reveals the expected security label.
- `INELIGIBLE_SECURITY_CONSTRAINT`: the prompt already requests secure
  implementation, a specific defense, or prevention of a security failure.
- `INELIGIBLE_UNSAFE_REQUEST`: the prompt requests exploitation, bypass,
  weakening, removal of protection, or intentionally unsafe behavior.
- `UNRESOLVED`: the prompt is mixed, underspecified, or cannot be classified
  under the frozen rubric.

The first three labels remain security-neutral candidates. The three
`INELIGIBLE_*` labels are excluded from a neutral baseline. `UNRESOLVED` is
conservatively excluded pending human decision.

## 6. Cluster Rubric

Relation labels are:

```text
SAME_TASK
SAME_TASK_VARIANT
DISTINCT_TASK
UNRESOLVED
```

- `SAME_TASK`: equivalent functional behavior and input/output contract.
- `SAME_TASK_VARIANT`: the same underlying task with presentation, language,
  context, or security-feature variation that must remain in one cluster.
- `DISTINCT_TASK`: shared wording does not imply the same task contract.
- `UNRESOLVED`: evidence is insufficient.

`SAME_TASK` and `SAME_TASK_VARIANT` merge relation components before any later
discover/confirm split. `DISTINCT_TASK` removes only the adjudicated ambiguous
edge. Any unresolved incident relation keeps the affected component
conservatively non-independent.

## 7. Decision Schema

Every Codex decision records:

- packet ID and dimension;
- pass ID (`A` or `B`);
- label and `HIGH`/`LOW` confidence;
- evidence quotes copied from the blinded prompt(s);
- concise rubric-grounded rationale;
- rubric version and packet content digest;
- annotator kind and identifier;
- decision timestamp and input manifest digest.

Decision import rejects unknown packets, duplicates, stale packet digests,
invalid labels, empty evidence, unrecognized rubric versions, and decisions
that contain fields hidden by the packet schema.

## 8. Artifacts and Immutability

```text
runs/dataset-adjudication/<run-id>/
  config.json
  commands.jsonl
  environment.json
  source-manifest.json
  packet-metadata.jsonl
  pass-a-packets.jsonl
  pass-b-packets.jsonl
  pass-a-decisions.jsonl
  pass-b-decisions.jsonl
  repeat-consistency.jsonl
  human-review-queue.jsonl
  human-review-template.jsonl
  agreement.json
  failures.jsonl
  report.json
  report.md
```

Packet-generation runs and reconciliation runs use new immutable run IDs.
No Stage 0 artifact is modified. Human decisions are imported into a later
run that records the parent adjudication run.

## 9. Pilot and Expansion Gates

1. Generate the complete deterministic packet set.
2. Freeze a pilot of 20 neutrality and 20 cluster packets using the configured
   seed, with source-stratified selection where possible.
3. Complete both Codex passes for the pilot.
4. Review every disagreement and low-confidence case; inspect packet blinding
   and rubric usability.
5. Freeze rubric v1 without using generated-code or Oracle outcomes.
6. Complete both passes for all 172 packets.
7. Generate the human queue and audit sample.

The pilot may clarify wording but must not silently relabel completed decisions.
If the rubric changes, use a new version and rerun every affected decision.

## 10. Non-Goals

Stage 1A does not:

- claim human annotation before human review;
- infer CWE labels for general benchmarks;
- create or validate missing functional contracts;
- use generated code, Oracle results, confirm outcomes, or causal estimates;
- modify Prompt TSG features or intervention definitions;
- freeze datasets, CWE families, sample sizes, models, or split ratios; or
- make security-only data eligible for the primary secure-and-functional ITT.

## 11. Acceptance Criteria

Stage 1A Codex work is complete when:

1. the immutable source manifest and packet set validate against Stage 0;
2. 117 neutrality and 55 cluster packets are present exactly once per pass;
3. pass order and A/B prompt order are deterministic but different where
   possible;
4. both Codex passes contain a valid decision for every packet;
5. repeat disagreements and all low-confidence decisions enter human review;
6. the remaining agreement pool is sampled at 20% per frozen stratum;
7. no hidden provenance field appears in annotator packets;
8. status remains `AWAITING_HUMAN_AUDIT`; and
9. commands, logs, configuration, intermediate outputs, failures, and results
   are preserved without overwriting Stage 0 or earlier Stage 1A runs.
