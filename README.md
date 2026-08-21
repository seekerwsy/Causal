# SecAware research artifact

SecAware is a compact, standard-library Python prototype for studying whether a
pre-specified prompt intervention changes generated-program security while
preserving functionality.

The repository now contains the method itself, not the historical deployment
platform. Model serving, provider clients, calibration campaigns, recovery
machinery, migration layers, and incident-specific scripts are intentionally
outside the active artifact. They remain recoverable from Git history.

## Method

The executable method is a short, auditable sequence:

1. Freeze the complete task population and outcome-blind candidates.
2. Rank candidates using externally supplied pre-treatment scores.
3. Freeze exactly four prompt arms: target, no-op, placebo, and generic.
4. Randomize every task-by-model block with a replayable seed.
5. Import independent security and functionality measurements.
6. Preserve unknown and terminal states for every randomized assignment.
7. Derive security, functionality, and joint outcomes deterministically.
8. Estimate target-minus-no-op ITT effects using registered denominators.
9. When outcomes are unknown, report worst-case bounds instead of filtering.
10. Write and independently verify an exact, content-addressed artifact bundle.

This prototype does not claim that a particular generator, security analyzer, or
functional evaluator is universally correct. Those systems produce measurement
inputs; they are deliberately separated from randomization and inference.

## Code map

The active implementation is under src/secaware:

| Module | Responsibility |
| --- | --- |
| representation.py | Frozen tasks, candidates, and population |
| prioritization.py | Deterministic pre-treatment ranking |
| intervention.py | Exact four-arm prompt interventions |
| randomization.py | Replayable complete-block assignment |
| measurement.py | Independent labels and total accounting |
| outcomes.py | Explicit deterministic outcome projection |
| inference.py | ITT estimates and unknown bounds |
| workflow.py | Freeze-to-analysis orchestration |
| records.py | Canonical serialization and content identities |
| artifact_io.py | Exact-closure artifact writing and verification |
| cli.py | Reproduce, verify, and summarize commands |

All scientific records are immutable dataclasses. Identities are SHA-256 hashes
of canonical JSON. Outcomes never enter population freeze, prioritization,
intervention construction, or randomization.

## Input boundary

The reproduce command accepts one JSON study specification containing:

- tasks: task_id, cluster_id, cwe, and prompt;
- candidates: task_id, feature_id, add/remove operation, and rationale;
- interventions: the four arm texts for each task;
- models, integer request slots, and a randomization seed;
- optionally, one terminal measurement per randomized coordinate.

A measurement contains task_id, model_id, request_slot, security, and
functionality. Security is secure, insecure, or unknown. Functionality is pass,
fail, or unknown. A terminal execution failure is represented by failure_stage
instead and remains in the ITT denominator.

The artifact rejects missing, duplicate, substituted, or post-randomization
filtered assignments.

## Reproduction

Install the package in an isolated Python 3.12 environment, then run:

    secaware reproduce study.json artifact
    secaware verify artifact
    secaware summarize artifact

The output directory must not already exist. It contains the frozen study,
randomization, optional outcomes and estimates, and an exact file manifest.
Verification rejects both modified files and unlisted extra files.

## Estimand

The primary contrast is the assigned-arm intention-to-treat difference:

    mean(Y | assigned target) - mean(Y | assigned no-op)

No assignment is removed after randomization. A point estimate is reported only
when both compared arms are fully observed. Otherwise the artifact reports the
minimum and maximum effect obtained by assigning every unknown outcome first to
failure and then to success.

Security and functionality are measured independently. Joint success equals one
only when both are positive; a known failure in either dimension makes joint
success zero; all other incomplete combinations remain unknown.

## Review

The default reviewer suite contains 24 focused tests and normally completes in
well under a minute:

    python -m pytest -q

Two additional milestone tests exercise the complete in-memory workflow and the
CLI plus independent bundle verification:

    python -m pytest -q -m milestone

See tests/README.md for the test boundary. The compact suite is the maintained
artifact; historical operational and field-by-field mutation tests are not part
of routine review.
