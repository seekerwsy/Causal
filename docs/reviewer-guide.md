# SecAware reviewer guide

SecAware is a research artifact, not a provider or deployment service. Review
the scientific path in this order:

1. src/secaware/representation.py
2. src/secaware/prioritization.py
3. src/secaware/intervention.py
4. src/secaware/randomization.py
5. src/secaware/adapters.py
6. src/secaware/measurement.py
7. src/secaware/outcomes.py
8. src/secaware/inference.py
9. src/secaware/workflow.py
10. src/secaware/artifact_io.py
11. src/secaware/cli.py

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

Review the freeze and analyze commands separately. A valid analysis must point
to an earlier exact-byte freeze artifact, reproduce its study identity, bind
the same measurement adapters, and close every randomized assignment.

Run the 24 default invariant tests with:

    python -m pytest -q

Run the two CLI milestones only after structural changes:

    python -m pytest -q -m milestone

See tests/README.md for the precise test boundary.
