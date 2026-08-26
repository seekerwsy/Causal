# Prompt Mechanism Study reviewer guide

Prompt Mechanism Study is a research artifact, not a provider or deployment service. Review
the scientific path in this order:

Start with the [current theory and method framework](current-method-theory-framework.md). It is a
review-oriented synthesis, while the normative prospective protocol remains the successor spec
linked below. The current coherent method is a Prompt-TSG-conditioned randomized intervention
study with an availability-gated observational-selector extension. The latest natural-Prompt
positivity audit did not authorize FCI execution.

1. src/prompt_mechanism_study/representation.py
2. src/prompt_mechanism_study/prioritization.py
3. src/prompt_mechanism_study/intervention.py
4. src/prompt_mechanism_study/randomization.py
5. src/prompt_mechanism_study/adapters.py
6. src/prompt_mechanism_study/measurement.py
7. src/prompt_mechanism_study/outcomes.py
8. src/prompt_mechanism_study/inference.py
9. src/prompt_mechanism_study/workflow.py
10. src/prompt_mechanism_study/cli.py

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

Review the freeze and analyze commands separately. A valid analysis must point
to an earlier exact-byte freeze artifact, reproduce its study identity, bind
the same measurement adapters, and close every randomized assignment.

Run the default invariant tests with:

    python -m pytest -q

Run the two CLI milestones only after structural changes:

    python -m pytest -q -m milestone

See tests/README.md for the precise test boundary.
