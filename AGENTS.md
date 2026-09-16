# Project-Level Agent Instructions

## Scope and Precedence

These instructions apply to the entire repository. Descendant `AGENTS.md`
files may add narrowly scoped requirements, but they must not weaken or
contradict these repository-wide constraints. Make any conflict explicit
before proceeding.

## Core Objective: Academic Innovation and a Reviewable Research Artifact

Prompt Mechanism Study is fundamentally an academic innovation project.
Prioritize the research questions, methodological novelty, valid empirical
evidence, and a clear scholarly contribution. Engineering serves these goals;
engineering completeness is not a research contribution by itself.

Keep implementation and process proportional to their scientific value:

- Use the simplest implementation and sufficient verification that support the
  approved method, credible conclusions, and necessary reproduction.
- Do not get bogged down in engineering polish, exhaustive edge cases, repeated
  checks, or elaborate bookkeeping that cannot materially affect the method,
  evidence, or a reviewer's understanding. Once relevant checks pass, continue
  the research unless a new change or concrete concern justifies more checking.
- Before adding infrastructure, scripts, artifacts, or procedural steps, identify
  the research question or scientific validity requirement they directly serve.
  Omit or consolidate work that has no such purpose.
- Explain progress through research decisions, usable evidence, and remaining
  scientific gaps; do not substitute engineering activity for research progress.

Maintain scientific clarity, inspectability, and reproducibility. The project
owner and reviewers must be able to understand
the complete active method without reconstructing it from development history,
deployment machinery, or several competing execution paths.

1. Maintain exactly one active, documented method path. Follow the normative
   protocol identified by the repository `README.md`. If that protocol is
   `SPECIFIED_DRAFT`, allow non-claim smoke, source preparation, verification,
   and explicitly authorized bounded development checks. Formal execution and
   scientific reporting remain prohibited unless the user explicitly selects
   an authorized frozen protocol. Development checks do not authorize provider
   spending, consumption of protected evaluation tasks, or formal role assignment.
2. Keep the active method legible as seven stages: representation,
   prioritization, hypothesis freeze, intervention/randomization, measurement,
   outcome assembly, and inference/reporting.
3. Keep Prompt TSG semantics distinct from causal structure. Prompt TSG edges
   are not causal edges. Generated code supplies independently measured
   security and functionality outcomes; it is not a primary-PAG variable or a
   causal mediator.
4. Use assigned-arm, deduplicated-task-unit ITT as the primary confirmatory
   analysis. A task unit is the paper-facing name for the independent unit
   historically stored as `semantic_cluster_id`; reserve "cluster" for the
   curation implementation and frozen legacy coordinates. Post-assignment
   fidelity, semantic compliance, generation success, and non-target drift are
   diagnostics, never denominator filters.
5. Keep the prospective primary safety outcome, oracle-evaluable secure-code
   yield, separate from code validity, Oracle support, unknown coverage,
   functionality, and secure-and-functional joint success.
6. Map every scientific claim and RQ output to the exact frozen input,
   configuration, implementation function, result field, and table builder.
   Demo, smoke, calibration, and development-canary results cannot be promoted
   to confirmatory evidence.
7. Treat discovery-population supplementation as optional pre-Discovery data
   preparation, not a new scientific stage. It may use only independently
   sourced natural task units, must be bounded to one outcome- and
   selector-blind round under a frozen coverage target, and must never use
   paraphrases, interventions, synthetic cell filling, FCI/RD scores, selector
   ranks, or Prompt-TSG relation support to choose acquisitions.
8. Use one outcome-blind discoverability Gate family for Atomic and Pair
   candidates. Pair eligibility never requires either factor to have been
   selected, ranked, or supported as an Atomic candidate; pure interactions
   remain admissible when their own context, compatibility, four-cell support,
   lineage-overlap, and fold requirements pass.
9. Keep context-modifier inference and Pair response-pattern labels inactive
   until their exact task assignment, joint bootstrap/multiplicity rule, and
   deterministic predicates are prospectively frozen. Missing rules must yield
   an explicit blocked status, never a guessed default, null label, or claim.

## Proportional Data, Intervention, and Oracle Requirements

1. Judge source usability against the research question and declared endpoint.
   Require an interpretable task, the relevant operation/security boundary, and
   the observable non-target behavior that must be preserved. Missing details
   unrelated to that comparison are limitations, not automatic task exclusions.
   Complete functional specification is required for a complete-functionality
   claim, not for every independently measurable security-policy effect. Keep
   partial functionality and joint success explicitly unknown where appropriate.
2. For an explicit prompt-requirement intervention, distinguish a requirement
   not expressed in the prompt from a security property absent in generated
   software. An addition may start from a prompt that does not express the target
   requirement, provided it does not contradict or alter required non-target
   behavior. This grants no claim that baseline code lacks the protection.
   Removal requires an identifiable source requirement. Define these semantics
   prospectively; never silently convert an unresolved semantic fact to absence.
3. Separate source screening from intervention protocolization. Natural sources
   need not contain a neutral control, placebo, or exact four-cell wording.
   Define and validate those comparisons in the intervention design, preserve
   non-target requirements, and freeze the applicable rules before formal use.
   Pending design work is not a source defect. Failures after assignment remain
   in the assigned-arm denominator and cannot trigger task replacement.
4. Qualify the Oracle for the endpoint, language, task family, and code forms
   actually admitted by the study. Unused languages or profiles must not block
   a narrower research scope. Preserve arm-blind measurement, secure/insecure/
   unknown distinctions, and checks that address plausible differential errors.
   Known positive, negative, and unknown examples are necessary checks, not a
   proof of universal accuracy. Use bounded representative validation and report
   measurement limitations; do not demand complete program verification or lower
   accuracy requirements solely to obtain more favorable results.
5. Apply the same source-screening principle to Atomic and Pair. Pair still
   needs its own interpretable joint context and a valid four-cell design; it
   does not need supported Atomic parents. Keep response-surface claims separate
   from stronger mechanism claims and require only the evidence each claim needs.
6. After a methodological revision, start with a small, explicit development
   scope that tests the scientific change. Prefer already exposed development
   material; record any new method-development exposure before using task-level
   feedback. Preserve protected evaluation inputs and all frozen review results.
   Earlier judgments retain their original rules; a new rule is not permission
   to relabel old unknowns or claim a larger eligible population without evidence.
7. Stop checking when the relevant scientific boundary has been demonstrated.
   Continue to the next research decision instead of restarting full-corpus
   cleaning, qualifying unused components, or adding another process layer.

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
   it out of default imports, active commands, active-path documentation, and
   the default reviewer suite. Document it only in explicitly archival or
   migration material.
5. Preserve ordinary development history through Git. Preserve an explicit
   archival bundle only when frozen evidence or reproducibility requires it,
   never as a parallel live code path. Never overwrite a frozen run or
   reinterpret an old artifact under a new schema or policy.
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
9. Keep server work under `/home/wsy/work/prompt-mechanism-study`. Use its
   `inputs`, `results`, and `archive` locations instead of creating additional
   deployment roots in the home directory. Preserve frozen inputs/results in a
   verified archive before clearing old directories; remove regenerable caches.
   Keep credentials owner-only on the server and out of transferred artifacts.

## Reviewability Requirements

1. Provide a short review guide that identifies the single active entry point,
   stage inputs and outputs, scientific invariants, and a reading order of no
   more than ten core files.
2. A reviewer must be able to run the current smoke reproduction and the
   independent result verifier without understanding internal deployment
   history. Once a claim-bearing frozen package exists, the same reviewer path
   must also reproduce its frozen scientific outputs.
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
5. Run focused tests while editing. Before declaring an affected reviewer path
   complete, validate it once from a clean supported environment and reproduce
   the existing frozen reference outputs affected by the change. Reuse verified
   results for unchanged components. Repeat or broaden checks only for a new
   change, a failure, or a concrete scientific concern. Do not imply that a
   formal reference result exists before protocol activation.

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
