# Project-Level Agent Instructions

## Scope and Precedence

These instructions apply to the entire repository. Descendant `AGENTS.md`
files may add narrowly scoped requirements, but they must not weaken or
contradict these repository-wide constraints. Make any conflict explicit
before proceeding.

## Core Objective: A Reviewable Research Artifact

SecAware is an academic research prototype and a peer-review artifact, not a
production service platform. Optimize for scientific clarity, inspectability,
and reproducibility. The project owner and reviewers must be able to understand
the complete active method without reconstructing it from development history,
deployment machinery, or several competing execution paths.

1. Maintain exactly one active, documented path from frozen inputs to the
   reported RQ outputs. New-protocol work uses the prospective successor in
   `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`
   unless the user explicitly selects another frozen protocol.
2. Keep the active method legible as seven stages: representation,
   prioritization, hypothesis freeze, intervention/randomization, measurement,
   outcome assembly, and inference/reporting.
3. Keep Prompt TSG semantics distinct from causal structure. Prompt TSG edges
   are not causal edges. Generated code supplies independently measured
   security and functionality outcomes; it is not a primary-PAG variable or a
   causal mediator.
4. Use assigned-arm, semantic-task-clustered ITT as the primary confirmatory
   analysis. Post-assignment fidelity, semantic compliance, generation
   success, and non-target drift are diagnostics, never denominator filters.
5. Keep the prospective primary safety outcome, oracle-evaluable secure-code
   yield, separate from code validity, Oracle support, unknown coverage,
   functionality, and secure-and-functional joint success.
6. Map every scientific claim and RQ output to the exact frozen input,
   configuration, implementation function, result field, and table builder.
   Demo, smoke, calibration, and development-canary results cannot be promoted
   to confirmatory evidence.

## Minimal Implementation Rules

1. Implement the smallest mechanism that directly supports the approved method
   or its reproducibility. Do not add production-grade orchestration,
   deployment, authorization, recovery, or compatibility machinery unless it
   is required for scientific validity or safe reviewer execution.
2. Do not create another framework, freezer, receipt, campaign type, schema
   generation, or wrapper script to repair a local defect. Fix the common cause
   in the existing active path.
3. Keep scripts thin. Put reusable scientific logic in importable modules and
   consolidate mechanical JSON, JSONL, hashing, atomic-write, environment, and
   manifest operations in a small shared artifact layer.
4. Preserve protocol versions only where they protect the interpretation of a
   frozen artifact. Mark non-active code as archival or migration-only and keep
   it out of default imports, commands, documentation, and tests.
5. Preserve history through Git and explicit archival bundles, not through
   parallel live code paths. Never overwrite a frozen run or reinterpret an old
   artifact under a new schema or policy.
6. State implementation choices concretely. A version label or abstract name
   is not an explanation of behavior.
7. Before scaling an experiment, validate the implementation and actual
   behavior on the smallest representative case. Record the exact environment,
   command, configuration, input identity, and output location needed to
   reproduce the run.
8. Diagnose unexpected results at the exact request, transformation,
   measurement, and aggregation steps. Do not explain anomalies as randomness
   or model differences without evidence, and do not permanently expand the
   architecture merely to preserve an operational incident.

## Reviewability Requirements

1. Provide a short review guide that identifies the single active entry point,
   stage inputs and outputs, scientific invariants, and a reading order of no
   more than ten core files.
2. A reviewer must be able to run a small smoke reproduction, the frozen full
   reproduction, and the result verifier without understanding internal
   deployment history.
3. Separate the reviewer artifact from the development archive. Exclude
   historical attempts, server administration, calibration exploration,
   temporary checkpoints, and unrelated frozen corpora from the default
   artifact package.
4. Prefer a transparent linear call graph over configuration-driven generic
   frameworks. Do not trade a few repeated declarative values for an abstraction
   that obscures the scientific procedure.

## Testing Requirements

1. Organize the default suite around scientific stages and invariants rather
   than historical incidents or implementation versions.
2. Retain tests that protect causal boundaries, randomization replay,
   task/arm/seed binding, outcome independence, unknown handling, total
   assignment accounting, estimator correctness, and one end-to-end smoke run.
3. Consolidate repeated fixture construction and artifact-tree helpers. Keep an
   independent result verifier where sharing production code would make the
   same error self-validating.
4. Put platform-hardening, legacy migration, historical policy-hash, deployment
   recovery, and exhaustive adversarial tests outside the default reviewer
   suite unless they support a stated claim or reviewer-safety boundary.
5. Run focused tests while editing. Before declaring the reviewer artifact
   complete, validate it from a clean supported environment and reproduce the
   frozen reference outputs.

## Research and Reporting Integrity

1. Distinguish `specified`, `implemented`, `tested`, `executed`, and `reported`.
   Passing a unit test does not prove that an experiment ran, and an engineering
   canary does not establish a scientific effect.
2. Never invent or infer a missing result. Preserve zero, harmful, conflicting,
   failed-backend, unknown, and non-evaluable outcomes required by the frozen
   protocol.
3. Do not change an RQ, estimand, arm family, denominator, multiplicity family,
   evidence level, task population, or model policy after examining its outcome.
   Post-hoc work must remain explicitly exploratory or start a new prospectively
   frozen study.
4. Paper prose must follow the research questions and verified evidence, not
   the implementation chronology. It may emphasize supported contributions but
   must not hide material limitations or adverse results.
5. When editing LaTeX or paper-facing figures and tables, compile after changes
   and visually inspect the rendered output. Quantitative claims require a
   traceable frozen artifact and table-building path.
