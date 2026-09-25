# Scientific test suite

Use Python 3.12 with the repository's `dev,selectors,languages` extras:

```text
python -m pytest -q
```

The default suite contains **104 cases in 80 test functions**. Its end-to-end
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
Python test code totals 5,700 lines.

Run the affected test file while editing. Before a reviewer-path change is
declared complete, use the installed package to run the default suite and the
independent verifier once. The 2026-09-25 framework contraction was validated in
a fresh Python 3.12.13 environment, installed with `dev,selectors,languages`:
**104 passed in 31.67 seconds**. The slowest checks were numerical power replay
(13.21 s), temporal non-ancestry (9.11 s) and exact qualification error bounds
(4.33 s). Focused checks are sufficient between changes.

Four tests of retired qualification/budget/freeze receipts were removed. Their
scientific boundaries now exercise the direct configuration in the existing smoke:
call ceilings, confirmation membership, task/arm/seed replay, rejection of formal
activation, and raw-request tampering even after bundle hashes are regenerated.
Numerical power and independent effect estimation tests are retained.

Reference comparison against `8e9241d2d` found:

- `shared_evidence_record.json` and `target_selector_yield_result.json` remain
  byte-identical; all four scientific RQ row collections are unchanged.
- RQ metadata drops the unused null formal-authorization field; the table ID
  changes accordingly. Old packages are not rewritten or accepted as new packages.
- Source `contracts.json` and `factor-states.json` remain byte-identical on the
  extraction reference. Compiling the source record reproduces the old saved
  graph exactly. The viewer and candidate path no longer depend on a graph cache.

Reproduction environment and output for this local check:
`C:/Users/WuSiyu/AppData/Local/Temp/causal-contraction-review-20260925/venv`
and `C:/Users/WuSiyu/AppData/Local/Temp/causal-contraction-review-20260925/tests`.
The portable command remains `python -m pytest -q`; no API calls were made.

Earlier suite reductions and frozen result replays remain on
`codex/pre-artifact-scope-20260923` at `f1cd0011`. The implementation and tests
before the module-boundary refactor are on
`codex/pre-module-boundaries-20260925` at `570219573`.

The current-wire candidate fixture now includes explicit applicability bindings.
An old four-field response is rejected rather than silently assigned a background.
Existing scope/requirement expectations remain checked; no historical format
compatibility test is needed in the production path.

The immediately preceding implementation and package reader are preserved on
`codex/pre-framework-contraction-20260925` at `8e9241d2d`.
