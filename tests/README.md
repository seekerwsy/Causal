# Scientific test suite

Use Python 3.12 with the repository's `dev,selectors,languages` extras:

```text
python -m pytest -q
```

The default suite contains **108 cases in 84 test functions**. Its end-to-end
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
qualification test still fails an incomplete representation. The bounded revision
test exercises extraction, source review and a full-record correction while saving
both versions; dangling references and explicit unknown coverage remain checked.
Authored graph fixtures use a strict test-only constructor, not the removed
production graph-response recovery adapter.

Source contracts and candidate assessments are tested separately. Failed scope
calls retain successful source extraction, absent assessments remain unknown,
and a state table cannot attach to a different source contract. Independent
qualification replays the saved source and assessment outputs; these changes
reuse the existing scientific scenarios without increasing the test case count.
Python test code totals 6,498 lines.

Run the affected test file while editing. Before a reviewer-path change is
declared complete, use the installed package to run the default suite and the
independent verifier once. The 2026-09-25 isolated run passed in 32.31 seconds;
its slowest checks were power replay (13.02 s), budget/dispatch replay (5.61 s),
and the seven-stage smoke (3.97 s). These protect statistical replay, planned
assignment accounting and independent result reconstruction. They need not run
after each local TSG edit. The focused TSG/input/candidate checks took 4.14 seconds.
All 20 smoke output files matched the preceding run byte for byte.

Earlier suite reductions and frozen result replays remain on
`codex/pre-artifact-scope-20260923` at `f1cd0011`. The implementation and tests
before the module-boundary refactor are on
`codex/pre-module-boundaries-20260925` at `570219573`.

The current-wire candidate fixture now includes explicit applicability bindings.
An old four-field response is rejected rather than silently assigned a background.
Existing scope/requirement expectations remain checked; no historical format
compatibility test is needed in the production path.
