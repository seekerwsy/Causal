# Reviewer guide

The [Atomic protocol](protocol.md), `phase-context-policy-v3`, is
`SPECIFIED_DRAFT`. The reviewer entry is `prompt-mechanism-study study smoke`.
It runs the seven scientific stages using synthetic tasks, offline responses
and a real FCI fit, then saves an independently verifiable
`NON_CLAIM_TEST_ARTIFACT`.

## Reproduction

Use Python 3.12 from the repository root:

```text
python -m pip install -e ".[dev,selectors,languages]"
python -m pytest -q
prompt-mechanism-study study smoke NEW_OUTPUT_DIRECTORY
prompt-mechanism-study study verify-result NEW_OUTPUT_DIRECTORY
```

Choose a new output directory. The default suite includes the end-to-end smoke,
independent result reconstruction and scientific boundary checks. It makes zero
paid provider calls and consumes zero protected evaluation tasks.

## Stage inputs and outputs

| Stage | Input | Output |
| --- | --- | --- |
| Representation | Original prompt and frozen source records | Bound requirements, objects, conditions and Atomic candidates |
| Prioritization | Task-unit states, scope, shared folds and discovery observations | Full/RD-only decisions with fixed K slots |
| Hypothesis freeze | Slots, models, populations, policies, call limit and analysis | Prospective study configuration and selected-policy dispatch |
| Intervention/randomization | Frozen task-policy variants and arms | Replayable task/arm/seed assignments |
| Measurement | Generated code and blinded evaluators | Code validity, security and functionality evidence |
| Outcome assembly | Every assignment and measurement/failure | Complete assigned-arm outcome ledger |
| Inference/reporting | Frozen task-unit ledger and analysis | ITT effects, status, uncertainty and independently checked tables |

## Scientific invariants

- One complete editable requirement defines an Atomic policy.
- Prompt TSG expresses source semantics. Generated code supplies independent
  security and functionality outcomes.
- The deduplicated task unit is the independent analysis unit; prompt variants,
  repeated seeds and arms retain their parent task identity.
- Every assigned task remains in the primary denominator. Compliance, code
  validity and non-target drift remain diagnostics.
- Security-unknown, terminal code and infrastructure failure remain explicit.
  Secure-code yield, Oracle evaluability, functionality and joint success have
  separate fields.
- Fixed selector slots retain empty and failed positions. A shared model effect
  is dispatched once and contributes to each selecting slot.
- Formal evidence levels are rejected under this draft. Context inference
  remains blocked until its prospective rules are frozen.

## Reading order

1. [Protocol](protocol.md): scientific decisions and formal gates.
2. [Workflow](../src/target_workflow.py): linear stage execution.
3. [Source representation](../src/tsg/prompt_contract.py): requirement bindings.
4. [Candidate construction](../src/tsg/candidate_construction.py): Atomic scope.
5. [Prioritization](../src/discovery/prioritization.py): folds, scores and fixed slots.
6. [Study design](../src/experiment/study_design.py): prospective inputs.
7. [Assignment](../src/experiment/randomization.py): task/arm/seed replay.
8. [Measurement](../src/measurement/evaluate.py): independent endpoints.
9. [Inference](../src/experiment/inference.py): task-unit ITT.
10. [Independent verifier](../src/verification/verifier.py): saved-result reconstruction.

## Saved package

| File | Contents |
| --- | --- |
| `study_config.json` | Role manifest, population, selection inputs, model scope, K, call limit and analysis |
| `confirmation_inputs.json` | Dispatch bound directly to its fixed-slot ledger, variants, randomization and measurement contract |
| `measurement_records.json` | Exact requests, raw code/responses, measured labels and functional review evidence |
| `shared_evidence_record.json` | All assignments, outcomes and task-unit inference |
| `target_selector_yield_result.json` | Fixed-slot yield including empty and failed slots |
| `rq_tables.json` | Reported rows independently rebuilt by the verifier |
| `manifest.json` | Exact-byte file integrity |

The workflow writes this package before invoking its independent readback
verifier. The verifier reconstructs assignment and inference independently of
the production randomizer and estimator. Measurement replay uses the declared
security implementation and retained evaluator responses. Oracle accuracy and
model quality require separate empirical qualification.

Source extraction saves `contracts.json`, separately bound `factor-states.json`
and retained `responses.json`. Graphs are compiled from the authoritative source
records. Current source-contract, graph and concept-catalog schemas are 4, 3 and
2 respectively. Saved records require exact fields and primitive types.

## Exposed development and frozen evidence

The [current development check](experiments/2026-10-07-controlled-repair.md)
documents prompt submissions, safety-gain selection and native target-access
measurement. Its independent replay is available through `study verify-repair`;
the [test guide](../tests/README.md) provides its separate test command.

Completed studies use the matching source archive and the
[archive reproduction guide](archive-reproduction.md). Their scripts, historical
tests and frozen formats remain in that isolated reproduction environment.
Source curation, historical administration and model-server operation are outside
the reviewer smoke.
