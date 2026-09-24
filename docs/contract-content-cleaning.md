# Prepared source inputs

The prototype starts with source tasks and supplied source-backed contracts.
It does not operate a second pipeline for producing, repairing and repeatedly
reviewing contracts. Input preparation is outcome-blind author work, not an
additional scientific stage. The [dataset specification](research-dataset-spec.md)
retains the frozen populations, exposure boundaries and source-review history.

## Required boundary

Preserve the original prompt and its identity, deduplicated task unit, provenance,
source evidence, and exposure/role restrictions. Supplied semantic judgments must
state their actual origin; importing a contract does not make it independently
reviewed. A valid hash or source quotation does not establish semantic correctness.
Unknown requirements remain unknown, and unrelated missing details do not exclude
a task from every candidate. No command here assigns formal evaluation roles.

New development tasks can use the existing task/plan input format. They need not
reconstruct an entire historical v4/v5 corpus. Any new exposure is recorded before
using task-level feedback, and protected tasks remain protected. Prepared inputs
still enter the same TSG extraction and seven-stage experiment path.

## Retained commands

| Command | Responsibility |
| --- | --- |
| `data prepare` | Import and normalize supported source datasets without executing source code. |
| `data freeze-contracts` | Import explicitly supplied source-backed contract responses. |
| `data dedup-candidates` | Construct outcome-blind duplicate candidates. |
| `data clusters` | Assemble exact/lineage task units from supplied records and decisions. |
| `data candidate-pool` | Screen prepared inputs using frozen exposure and review evidence. |
| `data verify-inputs` | Read-only verification of released v4/v5 bundles. |
| `data verify-source-review` | Independently replay a supplied source-review round. |

Use each command's `--help` for its input paths. For example:

```text
prompt-mechanism-study data verify-inputs data/dataset-curation/reviewer-task-unit-dataset-v5
```

Verification retains file identity, task partitions, evidence and frozen quality
semantics. It neither manufactures missing review decisions nor upgrades source
quality into candidate eligibility or complete functional measurement support.

## Removed preparation machinery

Automatic contract generation, evidence backfill/repair, review packet campaigns,
v4/v5 corpus production and closed-catalog qualification packet construction are
preserved at `6b0e8b220` on `codex/pre-input-contraction-20260924`. They have no live
compatibility path. Rebuild historical bundles with their captured implementation;
do not overwrite them or reinterpret old judgments under new rules.

The current change narrows implementation scope, not the experimental estimand,
FCI/RD rules, arm family or independent result verification. The protocol remains
`SPECIFIED_DRAFT`; no formal experiment or provider spending is authorized here.
