# Prompt Mechanism Study research artifact

Prompt Mechanism Study is a compact, auditable framework for testing whether a frozen prompt
intervention policy changes oracle-evaluable secure-code yield while preserving
functionality.

The artifact implements the scientific protocol and delegates environment-
specific execution to frozen adapters. It intentionally excludes model
deployment, remote transfer, campaign recovery, credential handling, and
provider-specific orchestration.

## Implemented method

The active path has three layers.

### 1. Representation and prioritization

- Freeze discover and confirm tasks before outcomes.
- Prevent one semantic task cluster from crossing the split.
- Freeze context query, actionable feature, ADD/REMOVE operation, outcome, and
  expected direction as candidate identities.
- Bind the complete candidate universe to a representation adapter.
- Bind every candidate score, deterministic tie break, rank, top-K slot, and
  selector adapter before confirmation.

The artifact executes ranking and top-K selection. A Prompt TSG extractor or
causal selector may produce the frozen universe and score manifest externally;
its name, version, and policy digest remain part of the study identity.

### 2. Intervention and randomization

- Freeze one `InterventionSpec` containing the mechanism, ADD/REMOVE operation,
  and natural-language instruction for the Target and Noop arms.
- Require every intervention text to come from the frozen LLM-executor adapter;
  the core applies the sole active edit rule by appending that text to the
  unchanged source prompt.
- Require an independent, contract-aware and outcome-blind LLM validator to
  record task preservation, contract satisfaction, unintended changes, and
  contradictions for every arm. Only `yes/yes/no/no` enters randomization.
- Freeze a finite realization distribution using positive integer weights.
- Materialize one complete task-realization bundle for every confirm task.
- Bind cluster, task, candidate, policy, realization, task bundle, model, and
  intervention spec into every complete-block identity.
- Pair Target and Noop inside every block using a replayable randomization seed
  and request-randomness slots.

### 3. Measurement and cluster-aware inference

- Freeze generator, Security Oracle, and functional-evaluator identities.
- Bind generator, Oracle, and functional raw-evidence digests for every result.
- Import measurements only after a separate immutable study freeze exists.
- Distinguish valid code, terminal no-code, invalid code, Oracle unknown, and
  infrastructure failure.
- Decompose each assignment into code-valid yield, Oracle evaluability,
  observed secure yield, latent secure upper support, functionality, and joint
  success.
- Keep terminal no-code and invalid code as assigned-arm zeros.
- Require infrastructure failures to be repaired or replayed before analysis.
- Estimate every candidate and model separately.
- Average request slots inside task-realization blocks, then apply frozen
  realization and within-cluster task weights, then weight semantic clusters
  equally.
- Report target-minus-no-op ITT, unknown bounds, and deterministic
  semantic-cluster simultaneous bootstrap intervals.

No treatment-fidelity diagnostic filters an assigned unit.

## External adapter boundary

Seven adapter identities are frozen:

| Adapter | Artifact responsibility |
| --- | --- |
| representation | Candidate-universe evidence |
| selector | Pre-outcome candidate scores |
| intervention executor | LLM production of free-form intervention text |
| intervention validator | Contract-aware, outcome-blind semantic validation |
| generator | Generated-code production |
| security oracle | Secure, insecure, or unknown decision |
| functional evaluator | Pass, fail, or unknown decision |

An adapter identity contains a kind, name, version, and policy SHA-256 digest.
Changing any of them changes the study identity. The core never silently
substitutes a producer. The study identity also binds the active method version
and the complete pre-outcome analysis plan.

## Commands

Freeze a protocol before measurement:

    prompt-mechanism-study freeze protocol.json freeze-artifact

After external generators and evaluators produce a complete measurement file:

    prompt-mechanism-study analyze freeze-artifact measurements.json analysis-artifact

Verify or inspect a bundle:

    prompt-mechanism-study verify freeze-artifact
    prompt-mechanism-study verify analysis-artifact
    prompt-mechanism-study summarize analysis-artifact

The freeze command rejects outcome fields. The analyze command replays the
study from the frozen protocol, verifies the exact-byte bundle, checks study
and adapter identities, and requires one measurement for every randomized
assignment.

The active functional Oracle is frozen in
`configs/functional-judge/functional-oracle-qwen37max.json`. Generated
Python must first pass AST parsing and bytecode compilation. A blinded LLM,
acting as a software-engineering reviewer, then judges the code against the
original functional task. Functionality passes only when both gates pass;
definite non-compliance fails, and unresolved static evidence remains unknown.
The functional Oracle is independent of and never replaces the static Security
Oracle. Its frozen engineering qualification is recorded in
`data/functional-judge/functional-oracle-qualification.json` (15/16 correct,
one false pass, zero invalid responses); those calibration cases are excluded
from experimental effect estimates.

Run the gate before the main experiment. The preflight makes no provider call;
the pilot covers one frozen case from each task family, and the remaining phase
is unavailable unless that pilot passes:

    prompt-mechanism-study judge-gate preflight judge-preflight \
      --gate-config configs/functional-judge/functional-oracle-qwen37max.json
    prompt-mechanism-study judge-gate pilot judge-pilot \
      --gate-config configs/functional-judge/functional-oracle-qwen37max.json
    prompt-mechanism-study judge-gate remaining judge-remaining --pilot-root judge-pilot \
      --gate-config configs/functional-judge/functional-oracle-qwen37max.json
    prompt-mechanism-study judge-gate finalize judge-result \
      --pilot-root judge-pilot --remaining-root judge-remaining \
      --gate-config configs/functional-judge/functional-oracle-qwen37max.json

Every attempted case is closed as its own exact-byte bundle before the phase
summary is written. Provider requests omit case identity, family, gold label,
arm, security outcome, and generator identity.

## Code map

| Module | Responsibility |
| --- | --- |
| adapters.py | Frozen external-producer identities |
| representation.py | Splits, semantic clusters, candidates, universe |
| prioritization.py | Score, rank, and top-K freeze |
| intervention.py | Intervention spec, LLM executions, semantic validation, prompt assembly |
| randomization.py | Complete-block assignment |
| measurement.py | External results and infrastructure boundary |
| outcomes.py | Total outcome decomposition |
| inference.py | Cluster-weighted ITT, bounds, simultaneous intervals |
| workflow.py | Prospective freeze and post-measurement analysis |
| records.py | Canonical content identities |
| artifact_io.py | Exact-byte bundle closure |
| cli.py | Freeze, analyze, verify, and summarize |

## Review

The default suite contains 24 focused scientific-invariant tests:

    python -m pytest -q

Two additional milestone tests execute the separated freeze and analyze CLI
path:

    python -m pytest -q -m milestone

The default suite is intentionally small. Historical deployment incidents,
provider diagnostics, campaign receipts, and field-by-field migration tests
remain in Git history rather than the active reviewer artifact.
