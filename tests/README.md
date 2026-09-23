# Scientific test suite

Use Python 3.12 with the repository's `dev,selectors,languages` extras:

```text
python -m pytest -q
```

The default suite contains **100 cases in 80 test functions**. Its end-to-end
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

The source producer has one integration case that checks the actual request and
response boundary: semantic repair returns content without evidence spans,
binding then runs separately, and failed localization remains pending independent
review with the raw failed binding preserved.

Run the affected test file while editing. Before a reviewer-path change is
declared complete, use the installed package to run the default suite and the
independent verifier once. Historical suite reductions and frozen result replays
remain on `codex/pre-artifact-scope-20260923` at `f1cd0011`.
