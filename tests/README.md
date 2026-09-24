# Scientific test suite

Use Python 3.12 with the repository's `dev,selectors,languages` extras:

```text
python -m pytest -q
```

The default suite contains **102 cases in 81 test functions**. Its end-to-end
smoke executes all seven stages with offline model responses and a real FCI fit
on synthetic observations. It also runs the independent saved-result verifier.
These checks make no paid provider calls and cannot establish real-model TSG or
Oracle accuracy.

| Boundary | Retained check |
| --- | --- |
| Source and task unit | Input identity, deduplication, source lineage, outcome-blind roles and protected-task separation |
| TSG and candidates | Requirement/target/condition/scope bindings, Atomic ADD/REMOVE and unknown distinct from absence |
| Discovery | FCI execution and failure, Full/RD-only comparability, fixed slots and shared dispatch |
| Assignment | Frozen task/arm/seed coordinates, replay and total accounting |
| Measurement | Code validity, secure/insecure/unknown, functionality and blinded evidence |
| Inference | Task-unit ITT, bootstrap, multiplicity and non-evaluable effects |
| Independent replay | Tamper detection and full offline smoke result |

Source-input tests read fixed synthetic v4/v5 bundles from
`fixtures/task-unit-bundles.json`, then tamper with their task partitions and
source evidence while updating hashes. The verifier must still reject them.
The fixture contains three invented tasks, captured from the former compiler's
passing test at `6b0e8b220`; it is neither natural evaluation data nor a scientific
result. Tests no longer rebuild a historical curation pipeline to check inputs.

Task-bound security tests retain unknown assignments and independent functionality
when permission targets or credential meaning are unavailable. Qualification tests
preserve separately valid profiles when another lacks support. Mocked proposal
calls exercise the real configurable evaluator boundary without network access.

TSG tests distinguish structural acceptance from semantic correctness: overlapping
source spans and a deliberately incorrect but structurally valid interpretation
are accepted, while dangling references and invalid locations are rejected.
Model-reported uncertainty remains explicit. Domain/role inference tests have
been replaced with direct model-assessment tests; the independent semantic
qualification test still fails an incomplete representation.

Run the affected test file while editing. Before a reviewer-path change is
declared complete, use the installed package to run the default suite and the
independent verifier once. Historical suite reductions and frozen result replays
remain on `codex/pre-artifact-scope-20260923` at `f1cd0011`.
