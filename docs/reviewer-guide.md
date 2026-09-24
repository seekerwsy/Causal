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
downstream freezes and arithmetic; it does not certify the FCI output or model
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
6. [Study design](../src/experiment/study_design.py): frozen study identities.
7. [Assignment](../src/experiment/randomization.py): task/arm/seed replay.
8. [Measurement](../src/measurement/evaluate.py): independent outcomes.
9. [Inference](../src/experiment/inference.py): task-unit ITT.
10. [Independent verification](../src/verification/verifier.py): saved-result replay.

The [test guide](../tests/README.md) identifies scientific boundaries checked by
the default suite. Source preparation and historical experiment administration
are not prerequisites to reproduce the smoke.

## Framework responsibilities

The framework-wide refactor starts from `dec567472`, preserved on local branch
`codex/pre-framework-refactor-20260924`. There is no compatibility copy of the
removed paths in the active package.

| Area | Current responsibility and retained boundary |
| --- | --- |
| Entry and source preparation | `cli.py` routes the study; `data/commands.py` contains author data commands. Source contracts and independent review decisions are supplied inputs; frozen v4/v5 identities, source evidence and task partitions remain verified. |
| Representation | `tsg/source_records.py` owns extraction attempts and record compilation; `prompt_contract_extract.py` orchestrates graph construction and scope assessment without a reverse import from the producer. Conditions, scope and unknown semantics remain unchanged. |
| Prioritization | `discovery/prioritization.py` retains the current PAG/FCI implementation, RD ranking, fixed candidate slots and Full/RD-only comparison. The unused adjacency-only adapter is removed. |
| Freeze and assignment | `experiment/study_planning.py`, `study_design.py` and `randomization.py` retain prospective scope, budgets, independent task units and exact arm/seed assignment. These checks implement research boundaries rather than historical recovery. |
| Measurement | `measurement/security_profiles.py` is the security implementation. Functional judgment remains separate; the native worker and its Docker adapter are together in `native_behavior.py`. Host-isolation protections remain. |
| Outcomes and reporting | `experiment/outcomes.py`, `inference.py` and `reporting.py` assemble assigned outcomes, estimate effects and build tables. Unused one-off paired/model summaries are removed. The frozen development screen remains distinct from confirmatory inference. |
| Independent verification | `verification/` retains its separate assignment and statistical replay. It does not import production estimators to manufacture agreement. |
| Shared mechanics | `llm.py` provides one explicit chat attempt for cloud or local models. `artifact_io.py` handles JSON and hashes; v4/v5 dataset identities and bytes remain distinct. |

The input contraction is preserved against `6b0e8b220` on local branch
`codex/pre-input-contraction-20260924`. Automatic contract production, evidence
repair loops, source-review packet production, v4/v5 corpus assembly and the
closed-catalog qualification packet builder are removed from the active package.
Raw source import and supplied-contract import remain available under `data`.
Use `data verify-inputs BUNDLE` for frozen v4/v5 inputs and
`data verify-source-review ROUND` for independently supplied historical review
records. See [the input boundary](contract-content-cleaning.md).

This is a deliberate reduction in preparation capability. It does not change
TSG extraction, FCI/RD selection, four-arm assignment, outcome accounting or
inference. Existing historical artifacts retain their original interpretation
and require their captured producer if rebuilding them is necessary. The formal
protocol remains inactive.

Validation of the input contraction on 2026-09-24 used the isolated Python 3.12
environment installed for the preceding framework review, with fresh test output
directories: 100 tests passed in 29.88 seconds. All 20 smoke files remain
byte-identical to the pre-refactor reference. The released v5 bundle still verifies
with 2,165 task units and manifest
`33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`.
All retained function bodies in the four reduced data modules are unchanged;
source imports and static unused-name checks pass. These checks involve no model
calls, new effect evidence or paper changes.

Python source under `src/` decreased from 35,115 to 29,670 physical lines
(including comments and blank lines), across 54 files. The data modules decreased
from 9,297 to 3,907 lines. These figures exclude fixtures, tests and documents;
fixed synthetic input fixtures now replace tests of the retired producers.
