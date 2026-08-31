# Task-unit data bundle

This document and the executable verifier in `task_unit_data.py` are the
authoritative data-structure contract. `research-dataset-spec.md` defines the
planned research populations but does not duplicate this field schema.

The compiler is the single active path from the completed seven-source
curation artifacts to the reviewer-facing task-unit corpus. It performs no
model calls, semantic re-clustering, Prompt TSG extraction, hypothesis
eligibility, formal role assignment, generation, measurement, or outcome
analysis.

## Build and verify

```powershell
prompt-mechanism-study data task-unit-bundle build `
  .codex-runtime/reviewer-task-unit-data-20260831-13-review-closed `
  --prepared-root .codex-runtime/external-gate-c-overlap-audit/seven-source-prepared-v2 `
  --clusters-root .codex-runtime/semantic-problem-pilot-final `
  --candidate-root .codex-runtime/dataset-final-quality-20260831-40-independent-quality `
  --contracts-root .codex-runtime/contract-recovery-adjudication-20260831-10 `
  --contract-reviews-root .codex-runtime/contract-quality-triage-37acead-20260831-03-r6-closed/final `
  --legacy-roles-root data/method/legacy-v5-role-bindings-v2 `
  --development-exclusions data/dataset-curation/contract-review-development-exclusions-v1.json

prompt-mechanism-study data task-unit-bundle verify `
  .codex-runtime/reviewer-task-unit-data-20260831-13-review-closed
```

The reference v4 build has manifest digest
`b61634973f0279522c06cd299389776828b74c2c298947a48e881fc94963e690`.
It contains 2,283 source records, 2,165 task units, and 2,165 directly joined
contracts. Quality remains 1,222 included, 930 pending contract repair, six
pending independent review, and seven source-defect exclusions. Technical
readiness is 166 when exposure is correctly excluded from that calculation;
141 of those tasks have no recorded method-development exposure. All 2,165
legacy contracts still require source-span enrichment, so this build closes the
reviewer schema and referential-integrity gap but does not claim full quality
closure.

## Authority boundaries

The linked records have distinct authority:

| File | Authority |
| --- | --- |
| `task-units.jsonl` | immutable source identity and exact representative model input |
| `functional-contracts.jsonl` | source-only functional semantics and blind review |
| `task-quality.jsonl` | source and contract quality only |
| `task-roles.jsonl` | exposure history and prospective-role restrictions |
| `source-lineages.jsonl` | source derivation partitions |
| `near-duplicate-groups.jsonl` | conservative formal-role allocation groups |
| `readiness-worklist.jsonl` | non-authoritative derived work view |
| `report.json` | referential-integrity results and population counts |
| `manifest.json` | exact file bytes, row counts, and schema identity |

All core tables join directly on `task_unit_id`. The bundle contains the
contract body; `.codex-runtime` inputs are build provenance, not reviewer-time
dependencies.

## Task identity

A task unit is the highest paper-facing sampling unit. Its representative
model-visible identity is the hash of the exact natural prompt, visible assets,
and render mode. Under the current render mode, only the exact source prompt is
shown to the generator; declared language and runtime remain pre-treatment
execution metadata and are explicitly marked non-model-visible.

Source members may include exact copies or frozen same-lineage descendants.
Every member must share one source lineage and declared language. The
representative is selected deterministically by preferring a record with a
source-test reference and then the smallest content-addressed record ID. Prompt
variants within a lineage are counted and exposed in `source_member_summary`;
they are not silently presented as identical inputs.

Semantic `same` or `uncertain` diagnostic edges do not merge task units. They
form a `near_duplicate_group_id`. The formal allocator must select at most one
task unit from each such group across the union of all prospective formal
roles. If a future design relaxes this rule, that group rather than the task
unit must become the resampling unit.

## Functional contracts and quality

Each contract binds its `source_prompt_sha256` to the representative prompt and
contains entrypoint, requirements, inputs, outputs, side effects, environment
dependencies, extraction reason, blind review, repair lineage, and record hash.
Legacy contracts retain the explicit status
`LEGACY_TEXT_CONTRACT_PENDING_SOURCE_SPAN_ENRICHMENT`. New extraction uses the
v8 protocol, requires one prompt-bound evidence span per requirement, permits
up to 32 irreducible requirements, and forbids silent truncation. Contract
producer failure is never treated as evidence that the source is insufficient.

Quality dispositions are independent of scope, mechanism, Oracle, runtime,
exposure, hypothesis applicability, and formal role:

- `QUALITY_INCLUDED`
- `QUALITY_PENDING_CONTRACT_REPAIR`
- `QUALITY_PENDING_INDEPENDENT_REVIEW`
- `QUALITY_EXCLUDED_SOURCE_DEFECT`
- `QUALITY_EXCLUDED_INSUFFICIENT_SPECIFICATION` (available for terminal
  source-based decisions after adjudication)

Full quality closure permits no pending disposition. A source is excluded for
insufficient specification only after repair and independent adjudication show
that the missing observable behavior belongs to the source, not to the
contract producer. Source prompts are immutable; a repaired prompt would be a
new derived task with a new identity.

Explicit security behavior in a source remains in its functional contract.
Security/control classification is not written into the base contract before
the method catalog is frozen. Later hypothesis eligibility must map the target
control requirement as the one allowed treatment delta; all non-target source
requirements remain invariants.

## Exposure and formal roles

Every normalized task records `SOURCE_CURATED`. Task-level information used to
change an extractor, selector, intervention, or policy records
`METHOD_DEVELOPMENT_VIEWED`. Viewing qualification or generation outcomes uses
the separate categories `QUALIFICATION_OUTCOME_VIEWED` and
`GENERATION_OUTCOME_VIEWED`.

Source-only curation under a frozen protocol does not by itself establish
method-development exposure. If task-level cleaning feedback is used to revise
the method, the affected task units must be added to the development-exclusion
ledger. The current bundle assigns no prospective formal role.

## Multi-axis readiness

`readiness-worklist.jsonl` is marked `DERIVED_VIEW`. Its authoritative inputs
are quality plus the current mechanism, Oracle, runtime, and functionality
registries. Each row exposes independent axes:

```text
quality_gate
scope_status
mechanism_registration_status
binding_status
oracle_status
runtime_status
functional_measurement_status
independent_quality_review_status
```

`readiness_summary_status`, `workstream`, and `primary_next_action` are
deterministic conveniences, not scientific attributes. Exposure never changes
technical readiness. Because Prompt TSG and the final target/control catalog
are not frozen, every current readiness row is
`PROVISIONAL_PENDING_METHOD_FREEZE` and must be recomputed after method freeze.
If one task later supports multiple targets, readiness becomes
`(task_unit_id, security_target_id)`-level rather than overloading this current
task-level view.

## Integrity gate and deferred stages

The verifier checks equal task populations, exact source partitioning,
representative selection, model-visible identity, contract/prompt hashes,
quality/contract versions, exposure records, lineage and near-duplicate
partitions, derived readiness summaries, canonical bytes, and file hashes. It
rejects old admission fields (`task_id`, ADD/REMOVE eligibility, arm protocol,
split) and all Prompt TSG, assignment, generated-code, and outcome fields in
the source-data tables.

Prompt TSG remains:

```text
status = NOT_GENERATED_PENDING_METHOD_FREEZE
extractor_id = null
catalog_sha256 = null
task_count = 0
```

Prompt TSG, hypothesis-specific ADD/REMOVE eligibility, formal allocation,
assignment, generation, measurement, and outcomes are separate successor
artifacts created only after their respective prospective freezes.
