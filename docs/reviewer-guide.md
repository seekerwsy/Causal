# Reviewer guide

The single active method is the [Atomic protocol](protocol.md),
`phase-context-policy-v3`, currently `SPECIFIED_DRAFT`. The runnable artifact is
an offline seven-stage smoke, **not** a formal effect result. It makes no model
provider calls and consumes no protected evaluation tasks. Historical development
outputs are preserved on local branch `codex/pre-artifact-scope-20260923` at
`f1cd0011`; they are outside this default reviewer path.
The closed-vocabulary TSG qualifier and fixed-registry task-to-mechanism
binding commands are available only in that historical implementation; the
current path constructs open-graph Atomic candidates.

All current code measurement uses `measurement/security_profiles.py`. Command
and SQL interpretation are checked directly at each sink; there is no legacy
Oracle followed by a corrective wrapper. The retained qualification command is
`qualification target-security-oracle`, with `--profile` for the declared scope.
The trace format and implementation hash identify the current implementation;
old result packages must be replayed with their captured implementation.

## Reproduce the current result

Use Python 3.12 from the repository root:

```text
python -m pip install -e ".[dev,selectors,languages]"
python -m pytest -q
prompt-mechanism-study study smoke NEW_OUTPUT_DIRECTORY
prompt-mechanism-study study verify-result NEW_OUTPUT_DIRECTORY
```

Choose a new output directory for each standalone smoke. The default tests also
run the smoke and independent result verifier. The smoke uses bundled synthetic
task units and offline code/review responses in `src/fixtures/reviewer_smoke.json`.
It performs a real FCI fit on fixture observations, freezes policies, creates
all four assigned arms, measures saved code, accounts for failures/unknowns and
computes task-unit results. The verifier independently replays the saved
prospective inputs, assignment, raw measurements and arithmetic; it does not certify the FCI output or model
quality. The result is marked `NON_CLAIM_TEST_ARTIFACT`.

| Stage | Input | Saved output |
| --- | --- | --- |
| Representation | Original prompt and frozen source records | TSG requirements, objects, conditions and candidate bindings |
| Prioritization | Task-unit factor states, qualified scope and fixture outcomes | Full/RD-only fixed-slot decisions; FCI adjacency is a selection input, not a causal effect |
| Hypothesis freeze | Candidate slots, task/model scope and policies | Pre-outcome policy and comparison identities |
| Intervention/randomization | Frozen task-policy pairs and arms | Task/arm/seed assignments and edited prompts |
| Measurement | Raw generated code and blinded evaluators | Code validity, security secure/insecure/unknown, functionality pass/fail/unknown |
| Outcome assembly | Every assignment and its measurement/failure | Complete assigned-arm ledger |
| Inference/reporting | Frozen task-unit ledger | ITT effects, uncertainty/status, result table and independent replay |

The [scope preflight](artifact-scope-preflight.md) is a separate, outcome-blind
inventory check. Run `python scripts/scope_inventory.py` to recount it from the
bundled v4 task pool. It makes **zero formal admissions**. Its generated-code
comparison is explicitly a development diagnostic on the archived branch.

## Scientific boundaries

- One complete editable Atomic requirement defines a policy. TSG edges express
  source meaning; they are not FCI causal edges.
- The deduplicated task unit is the independent analysis unit. Repeated seeds,
  arms and prompt variants remain linked to it.
- The primary comparison uses all assigned task units. Post-assignment fidelity,
  model compliance, code validity, functionality and non-target drift do not
  remove observations from its denominator.
- A valid code sample can be security-unknown. Unknown contributes no observed
  secure-code yield, is not labeled insecure, and remains visible by arm.
  Functionality and secure-and-functional success are separate results.
- The same frozen comparison rules and independent verifier must be used for
  any future claim-bearing package. This draft artifact supports no such claim.

## Read the implementation

1. [Protocol](protocol.md): active decisions and remaining formal gates.
2. [Workflow](../src/target_workflow.py): linear seven-stage call graph.
3. [Source representation](../src/tsg/prompt_contract.py): bound requirements.
4. [Candidate construction](../src/tsg/candidate_construction.py): Atomic scope.
5. [Prioritization](../src/discovery/prioritization.py): FCI and RD-only slots.
6. [Study design](../src/experiment/study_design.py): prospective configuration and confirmation inputs.
7. [Assignment](../src/experiment/randomization.py): task/arm/seed replay.
8. [Measurement](../src/measurement/evaluate.py): independent outcomes.
9. [Inference](../src/experiment/inference.py): task-unit ITT.
10. [Independent verification](../src/verification/verifier.py): saved-result replay.

The [test guide](../tests/README.md) identifies scientific boundaries checked by
the default suite. Source preparation and historical experiment administration
are not prerequisites to reproduce the smoke.

## Module and artifact boundaries

The workflow calls stage functions and saves their outputs. Stage modules do not
call back into the workflow. `experiment/reporting.py` only builds result tables;
`target_workflow.write_target_result_bundle` calls the public independent verifier
and writes the reviewer package. The saved package has six business files plus
`manifest.json` for byte integrity:

| File | Contents |
| --- | --- |
| `study_config.json` | Original role manifest, population lineage, selection inputs/configuration, models, K, call limit and inference plan; constructed before selection. |
| `confirmation_inputs.json` | Selected-policy dispatch, task variants, randomization plan and task-bound measurement contract; constructed and checked before measurement. |
| `measurement_records.json` | Every assignment's exact generation request, raw response/code, measured labels and functional review evidence. |
| `shared_evidence_record.json` | All assignments/outcomes and task-unit inference, including unknown and failure accounting. |
| `target_selector_yield_result.json` | Fixed-slot yield, retaining empty or failed slots. |
| `rq_tables.json` | Result rows rebuilt independently by the verifier. |

No budget-qualification receipt, repeated hash index or report-authorization
receipt is required. The verifier independently reconstructs task/arm/seed
allocation, raw-record outcome mapping, statistical estimates and result rows.
It does not call the production randomizer or estimator. Security-profile replay
uses the declared measurement implementation; it does not prove Oracle accuracy.
The package's role and population records preserve the prospective data boundaries.

The active protocol is still `SPECIFIED_DRAFT`. Formal evidence levels are rejected;
changing a saved flag cannot authorize a claim. The retired administration classes
are not replaced by permissive qualification defaults. Formal execution still
requires an authorized protocol and its empirical qualifications. Numerical
power planning and independent power replay remain in the existing modules;
endpoint-specific Oracle and representation qualifications remain available.

The representation path separates source records from candidate judgments:

| Artifact | Meaning and consumers |
| --- | --- |
| `contracts.json` | The sole authoritative source representation, including facts, relations, conditions, scope, source uncertainty and its catalog. Graphs are compiled on demand for candidates, assessment and visualization. |
| `factor-states.json` | Candidate applicability/expression judgments tied to the exact source contract; scope binding and discovery consume an assessed graph projection. |
| `responses.json` | Raw extraction/review/assessment requests and responses, including separate failures; independent qualification replays each output. |

A failed candidate assessment does not mark successful source extraction as
failed. Missing judgments remain unknown and still reduce candidate coverage.
The viewer compiles the source projection and displays the separate assessments
on that graph. `graphs.json` and the duplicate catalog collection are no longer saved. It does not maintain another interpretation of source semantics.
Source-contract schema 4 replaces the combined schema 3; graph schema 3 and
concept-catalog schema 2 are unchanged. Replay old frozen contracts with their
captured Git version, rather than converting them in the active method.

Qualification depends on extraction for retained-response replay; extraction
never imports qualification. The CLI validates a prospective reference before
model calls. Response schemas belong to `source_records.py`; the low-level codec
does not dispatch back to that producer. No new module, generic stage framework,
semantic rule engine or compatibility path was added.

The preceding complete checkout is preserved on
`codex/pre-framework-contraction-20260925` at `8e9241d2d`. Replay historical
packages with their captured code; do not rewrite frozen evidence. This change
removes storage and administration layers, without changing FCI/RD selection,
Atomic four-arm assignment, endpoints, task-unit ITT or independent result arithmetic.

Validation details are recorded in the [test guide](../tests/README.md).
