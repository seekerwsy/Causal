# Prompt Mechanism Study reviewer guide

Prompt Mechanism Study is a research artifact, not a provider or deployment service. Review
the scientific path in this order:

Start with the [current theory and method framework](current-method-theory-framework.md). It is a
review-oriented synthesis, while the normative prospective protocol remains the successor spec
linked below. The current coherent method is a Prompt-TSG-conditioned randomized intervention
study with an availability-gated observational-selector extension. The latest natural-Prompt
positivity audit did not authorize FCI execution.

The single prospective command is `prompt-mechanism-study`. Its subcommands are
stage boundaries in one seven-stage method, not competing frameworks:

- `selector-study` freezes and verifies the availability-gated five-selector
  comparison and its selector-invariant intervention bridge; its
  `compare-representations` phase compares two complete selector funnels for
  RQ2 and labels the result as end-to-end rather than a pure selector effect;
- `successor-experiment` preflights, runs, or independently verifies one atomic
  ADD/REMOVE four-arm study;
- `interaction-selector` freezes and verifies outcome-blind pair selection;
- `factorial-experiment` preflights, runs, or independently verifies the `2 x
  2` extension.

Read at most these ten scientific core files, in order:

1. docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md
2. src/prompt_mechanism_study/prompt_tsg.py
3. src/prompt_mechanism_study/mechanisms.py
4. src/prompt_mechanism_study/prioritization.py
5. src/prompt_mechanism_study/intervention.py
6. src/prompt_mechanism_study/randomization.py
7. src/prompt_mechanism_study/measurement.py
8. src/prompt_mechanism_study/outcomes.py
9. src/prompt_mechanism_study/inference.py
10. src/prompt_mechanism_study/workflow.py

The `*_experiment.py` entry modules provide explicit linear artifact
orchestration around those stages. The matching `*_verify.py` modules
independently reconstruct reported coordinates; `artifact_io.py` and
`records.py` are shared serialization support.

The normative prospective design remains the
[context-conditioned intervention policy framework](superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).
This compact implementation intentionally keeps one auditable scientific path:

- candidate universes, selector inputs/ranks, bridge maps, and pair selections
  are frozen and semantically replayable;
- the active selector is exactly schema 2.0; schema 1.0 is reachable only
  through explicitly archival APIs and CLI phases;
- pair selection embeds the representative task text and Prompt TSG, then
  recomputes each catalog-bound relation motif without arm or outcome data;
- active successor and schema-1.1 factorial runs require a separately written,
  verified pre-outcome materialization containing exact prompt variants,
  variant-TSG projections, assignment bindings, and execution order;
- policy freeze, randomization, outcome assembly, and inference are implemented
  in the artifact;
- generator, Oracle, and functional-evaluator execution occurs behind frozen
  adapter contracts;
- prospective result verifiers replay frozen provider responses through code
  extraction, syntax/compilation, Security Oracle, Functional Judge,
  Measurement, total ledger, and inference without another provider call;
- schema-1.1 factorial inference resamples the global task-unit union once per
  replicate, preserves partially overlapping pair support, uses
  replicate-specific studentized max-|T| families, and fails closed on
  inadequate valid-replicate support or zero standard error;
- its security-interaction permission is separate from practical-success
  permission; functionality non-inferiority is claim-bearing only when it was
  separately powered and its simultaneous `A11 - A00` lower bound clears the
  frozen margin;
- active successor and schema-1.1 factorial plans both require the ordered five
  endpoints; their unknown Gate uses valid code as its denominator, and a powered
  functionality Gate must carry a study-specific qualification sealed before
  outcomes;
- deployment, credentials, retries, recovery, and campaign administration are
  outside the active method.

Only `prompt-mechanism-study` is installed as a console command. The older
four-arm runner remains available through the explicitly archival module
`python -m prompt_mechanism_study.four_arm_cli`; its tracked Qwen bundles are
legacy/pilot evidence, not a second prospective protocol. The historical
minimal-kernel and two-arm paths are reachable only through commands whose
names start with `archival-`. None can be promoted under the successor
ADD/REMOVE policy without a new pre-outcome freeze.

The currently executed confirmation contract is
`configs/formal/factorial-sql-confirm-qwen35-v3.json`. Its stage boundary is:

    corpus/Prompt TSG -> pair binding -> four-cell prompt freeze -> complete-block
    randomization -> independent security/functionality measurement -> total
    outcome ledger -> task-unit ITT -> independent verification

Every randomized assignment must appear exactly once. `unknown`, invalid code,
functional failure, treatment collapse, and non-target drift are retained or
reported under their declared boundary and never used as denominator filters.

Implementation status is not effect evidence. The successor, five-selector,
pair-selector, and generalized multi-pair/multi-model paths are implemented and
reviewer-tested, but have not yet produced a new prospectively frozen provider
run. The RQ2 comparison runner is also implemented and replayable, but no two
new confirmatory representation funnels have been executed for it. The two
tracked schema-1.0 factorial result bundles remain the current formal effect
evidence for these latest paths; they are verified as historical schema-1.0
results, not silently migrated to schema 1.1.

Run the default invariant tests with:

    python -m pytest -q

Run the structural milestone suite only after method-level changes:

    python -m pytest -q -m milestone

The smallest active factorial reproduction is:

    python -m pytest -q -m milestone tests/test_factorial_reviewer_smoke.py

This is a 16-assignment, zero-network schema-1.1 smoke. It uses deterministic
provider responses only to exercise the frozen transport contracts, runs the
real local Security Oracle, writes its result only under the test temporary
directory, disables all scientific claims and functionality-power claims, and
must never be cited as effect evidence. Its `STRUCTURAL_SMOKE_ONLY` functional
qualification is rejected by confirmatory and other claim-bearing configs.

See tests/README.md for the precise test boundary.
