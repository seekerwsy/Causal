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
