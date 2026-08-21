# SecAware reviewer guide

SecAware is a research artifact, not a production service. Review the scientific
path before the operational utilities. The active path is:

1. represent task and prompt context;
2. prioritize and freeze a hypothesis before outcomes;
3. construct and randomize the intervention;
4. generate code and measure functional and security outcomes independently;
5. assemble outcomes and report inference without upgrading missingness or
   exploratory evidence into confirmatory claims.

The normative design is the
[`context-conditioned intervention policy framework`](superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).

## Core implementation files

Read these files in order:

1. `src/secaware/pipeline/stages/prompt_extraction.py`
2. `src/secaware/pipeline/stages/fci_discovery.py`
3. `src/secaware/pipeline/stages/randomization.py`
4. `src/secaware/intervention/executors.py`
5. `src/secaware/pipeline/stages/confirmation_generation.py`
6. `src/secaware/pipeline/stages/functional_judge.py`
7. `src/secaware/pipeline/stages/confirmation_oracle.py`
8. `src/secaware/pipeline/stages/functional_outcomes.py`
9. `src/secaware/pipeline/stages/effects.py`
10. `src/secaware/pipeline/stages/reporting.py`

The Functional Judge calibration is supporting measurement validation, not a
second experiment framework. Its active reviewer path is the v3 prompt and
schema in `src/secaware/functional_judge/`, the 24-case frozen plan in
`scripts/plan_functional_judge_v3_single_candidate.py`, the existing Judge
runner, and `scripts/analyze_functional_judge_v3_single_candidate.py`. The v3
plan and analyzer still reuse the frozen case loaders and candidate-summary
logic in the older paired planner/analyzer; those two imports are the remaining
calibration refactoring boundary, not an additional executable path.

## What is intentionally absent

- no separate campaign or receipt framework in the active v3 calibration path;
- no reuse of failed historical Judge traces as fresh evidence;
- no automatic conversion of development diagnostics into scientific claims;
- no security label supplied by the prompt graph or the functional Judge;
- no overwrite of a completed artifact root.

Tests should be read by the invariant they protect: assignment and treatment
integrity, measurement independence, missingness, and estimator/reporting
semantics. Historical deployment hardening and superseded campaign machinery
are not part of the reviewer-facing execution path.
