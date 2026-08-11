# Dataset Adjudication Stage 1A Implementation Plan

**Goal:** Implement and execute Scheme B LLM-assisted adjudication with a hard
human-audit gate over the frozen Stage 0 dataset audit.

## Task 1: Schemas, configuration, and source validation

- Add strict persisted schemas for packet metadata, blinded packets, Codex
  decisions, consistency records, and human-review entries.
- Add `configs/dataset-adjudication/adjudication-v1.json` with seed, rubric,
  sampling fraction, source run, and expected packet counts.
- Validate the Stage 0 report status, stable digest, artifact SHA-256 values,
  and record count before packet generation.
- Reject model/API/provider configuration in this local adjudication command.

## Task 2: Deterministic packet generation

- Select all 101 neutrality-unresolved and 16 obvious-conflict records.
- Rebuild Stage 0 cluster candidates using the existing bounded clustering
  implementation and select all 55 unresolved relations.
- Store complete provenance in `packet-metadata.jsonl`.
- Produce two blinded, deterministically shuffled packet files with reversed
  left/right presentation for cluster pairs when possible.
- Assert that hidden metadata cannot appear in blinded packet schemas.

## Task 3: Decision validation and reconciliation

- Import externally authored Codex pass files through strict schema validation.
- Require exact packet coverage and matching packet digests.
- Reconcile labels and confidence without resolving disagreements.
- Route disagreements and any low-confidence decision to human review.
- Deterministically sample 20% of remaining high-confidence agreements per
  `(dimension, source stratum)`, minimum one per non-empty stratum.
- Emit agreement counts, raw agreement, label distributions, and review-reason
  counts. Do not report human inter-rater statistics.

## Task 4: CLI and immutable run coordinator

- Register packet-generation and reconciliation commands.
- Use staging, complete-artifact validation, atomic publication, unique run
  IDs, parent-run lineage, environment/Git provenance, and structured failure
  artifacts.
- Provide an explicit human-review template; never auto-fill human decisions.

## Task 5: Pilot execution

- Generate all packets from `stage0-combined-20260810-08`.
- Freeze 20 neutrality and 20 cluster pilot packet IDs.
- Complete pass A and pass B in shuffled order.
- Inspect disagreements, low confidence, label definitions, blinding, and
  evidence quality.
- If rubric wording changes, increment its version and invalidate pilot
  decisions before expansion.

## Task 6: Full Codex adjudication and human queue

- Complete both passes for all 117 neutrality and 55 cluster packets.
- Validate coverage and reconcile.
- Produce the full human-review queue and deterministic 20% agreement audit.
- Preserve status `AWAITING_HUMAN_AUDIT` and report the exact remaining human
  workload.

## Task 7: Verification and handoff

- Run format/static checks available in the fixed environment.
- Run adjudication unit tests, dataset-audit adjacency tests, CLI tests, and
  immutable-run regression tests.
- Do not repeat the long full repository suite unless the changed boundary or
  an ordinary regression indicates it is necessary.
- Document exact commands, failures, repairs, counts, timing, commit, machine,
  paths, and artifact digests.
- Commit implementation and runtime-independent documentation; keep immutable
  adjudication run artifacts locally under the ignored run root.
