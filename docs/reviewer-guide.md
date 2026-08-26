# Prompt Mechanism Study reviewer guide

Prompt Mechanism Study is a research artifact, not a provider or deployment service. Review
the scientific path in this order:

Start with the [current theory and method framework](current-method-theory-framework.md). It is a
review-oriented synthesis, while the normative prospective protocol remains the successor spec
linked below. The current coherent method is a Prompt-TSG-conditioned randomized intervention
study with an availability-gated observational-selector extension. The latest natural-Prompt
positivity audit did not authorize FCI execution.

The active pairwise path has one linear entry point,
`factorial_experiment.run_factorial_experiment`. Read at most these ten core
files, in order:

1. src/prompt_mechanism_study/mechanisms.py
2. src/prompt_mechanism_study/factorial_corpus.py
3. src/prompt_mechanism_study/intervention.py
4. src/prompt_mechanism_study/randomization.py
5. src/prompt_mechanism_study/factorial_experiment.py
6. src/prompt_mechanism_study/security_profiles.py
7. src/prompt_mechanism_study/functional_judge.py
8. src/prompt_mechanism_study/outcomes.py
9. src/prompt_mechanism_study/inference.py
10. src/prompt_mechanism_study/factorial_verify.py

`artifact_io.py` and `records.py` are shared serialization support, not
additional scientific stages.

The normative prospective design remains the
[context-conditioned intervention policy framework](superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).
This compact implementation intentionally chooses one auditable active path:

- candidate universes and selector scores are frozen external evidence;
- ranking, policy freeze, randomization, outcome assembly, and inference are
  implemented in the artifact;
- generator, Oracle, and functional-evaluator execution occurs behind frozen
  adapter contracts;
- deployment, credentials, retries, recovery, and campaign administration are
  outside the active method.

The `prompt-mechanism-four-arm` command and its tracked Qwen result bundles reproduce legacy/pilot
four-arm studies. They are not a second prospective protocol and cannot be promoted to evidence
under the successor ADD/REMOVE policy without a new pre-outcome freeze.

The active confirmation contract is
`configs/formal/factorial-sql-confirm-qwen35-v3.json`. Its stage boundary is:

    corpus/Prompt TSG -> pair binding -> four-cell prompt freeze -> complete-block
    randomization -> independent security/functionality measurement -> total
    outcome ledger -> task-unit ITT -> independent verification

Every randomized assignment must appear exactly once. `unknown`, invalid code,
functional failure, treatment collapse, and non-target drift are retained or
reported under their declared boundary and never used as denominator filters.

Run the default invariant tests with:

    python -m pytest -q

Run the two CLI milestones only after structural changes:

    python -m pytest -q -m milestone

See tests/README.md for the precise test boundary.
