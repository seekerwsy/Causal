# Prompt Mechanism Study research artifact

Prompt Mechanism Study is a compact academic artifact for testing whether a
frozen prompt intervention changes Oracle-evaluable secure-code yield while
preserving functionality. It is a research prototype, not a deployment or
campaign-management platform.

The [current theory and method framework](docs/current-method-theory-framework.md) gives the
paper-facing objects, causal boundaries, seven stages, implementation status, and current gates.
The normative prospective protocol remains the successor specification; tracked legacy/pilot
results are not silently upgraded to that protocol.

## Method at a glance

```text
source benchmark records
        -> deduplicated task units
        -> one representative prompt per unit
        -> Prompt TSG and mechanism binding
        -> discovery support gate and hypothesis freeze
        -> operation-specific assigned prompt arms
        -> code generation
        -> independent security and functionality measurement
        -> assigned-arm task-unit ITT
```

### Terminology

- A **source record** is one prompt and its metadata from a benchmark.
- A **task unit** is one independent, cross-source-deduplicated experimental
  unit. It may represent one source record or several equivalent records.
- A **task** is the representative prompt executed for a task unit. The active
  four-arm studies use exactly one task per unit, so `task_id` is the analysis
  key.
- A **Prompt TSG** is the typed semantic representation of that representative
  prompt. It is not a causal graph and is not the resampling unit.

Older frozen artifacts use `semantic_cluster_id`, `cluster_id`, and
`semantic_task_cluster_id` for the task-unit coordinate. Those physical field
names remain immutable for reproduction. New method prose and prospective
protocols use **task unit**; "cluster" is otherwise reserved for the internal
deduplication step that groups source records.

## Single active method

The method is organized as seven visible stages.

1. **Representation.** Normalize source records, form conservative task units,
   choose one representative prompt, and extract bounded Prompt TSG facts.
2. **Prioritization.** Audit natural-prompt feature support and source overlap;
   run family-local selectors only after that outcome-blind gate passes.
3. **Hypothesis freeze.** Freeze task units, Prompt TSG bindings, mechanism
   registry, model, Oracles, arm texts, seeds, estimands, and multiplicity.
4. **Intervention and randomization.** Materialize the frozen ADD- or
   REMOVE-specific prompt variants and randomize their execution order without
   consulting generated outcomes.
5. **Measurement.** Generate code, check Python syntax/compilation, run the
   static Security Oracle, and run the blinded Functional Judge independently.
6. **Outcome assembly.** Account for every assignment and preserve invalid,
   insecure, unknown, failed, and functional outcomes without filtering.
7. **Inference and reporting.** Estimate paired assigned-arm ITT over equally
   weighted task units, report unknown bounds, and build the frozen result
   report.

Prompt TSG selects an applicable mechanism from prompt evidence. It does not
guarantee that generated code realizes that mechanism, and generated code is
not treated as a causal mediator. Realization and non-target drift are
diagnostics only.

## Prospective four-arm policies

Each frozen ADD or REMOVE hypothesis has four policy roles. The primary
contrast is always Target versus its operation-matched No-op:

| Operation | Target | No-op | Placebo/Sham | Generic |
| --- | --- | --- | --- | --- |
| ADD | add the concrete mechanism requirement | matched rewrite while the feature remains absent | length-matched presentation-only edit | generic security reminder |
| REMOVE | remove the concrete requirement using its frozen neutral counterpart | matched edit while retaining the requirement | length-matched unrelated edit | replace the concrete requirement with generic security guidance |

Placebo/sham and generic arms are secondary specificity controls. No arm is
removed from the ITT denominator because generated code ignored its instruction.
The earlier `absent/specific/generic/placebo` studies retain their frozen legacy
estimands; they are not reinterpreted as prospective ADD/REMOVE confirmation.

## Pairwise factorial extension

The active prospective extension tests two independently editable atomic Prompt
features in a complete `2 x 2` block:

```text
A00 = No-op 1 + No-op 2
A10 = Target 1 + No-op 2
A01 = No-op 1 + Target 2
A11 = Target 1 + Target 2
```

It remains one policy family inside the same seven-stage method. Prompt TSG
supplies an outcome-blind context and mechanism binding; it is not used as a
causal graph. Every task-unit/realization/model block contains all four cells,
and assigned cell is the treatment. The primary pair estimand is the
task-unit-weighted risk-difference interaction
`mu11 - mu10 - mu01 + mu00`. Factor fidelity and generated-code style remain
diagnostics and never filter the ITT denominator.

The completed bounded canary paired SQL value parameterization with a literal-map
allow-list for dynamic SQL identifiers and exercised both intervention orders.
It closed all 40 assignments, but its task contract already encouraged
identifier rejection and its Oracle accepted only literal maps. The observed
cell difference is therefore retained as implementation evidence, not as a
security-effect result.

The formal v3 confirmation used the equivalence-aware v2 Oracle and 30 controlled
task units. The v2 Oracle accepts both literal maps and dominating finite-domain
membership guards. Both operator orders remained in the frozen realization
distribution, giving 240 assignments for the Qwen3.5 model. The run completed and
was independently verified. Its primary interaction was zero with a simultaneous
interval of `[-0.0833, +0.0833]`; A00 was already 96.7% secure, revealing a severe
from-scratch baseline ceiling. This is a formal bounded null result, not evidence
that the method failed to run or that prompt mechanisms never matter. See
`docs/experiments/2026-08-27-factorial-sql-confirm-v3-results.md`.

## Outcomes and evidence boundary

The primary safety outcome is observed Oracle-evaluable secure-code yield.
Code validity, Oracle evaluability, unknown coverage, functionality, and
secure-and-functional joint success remain separate fields.

The Functional Judge is AST/compilation plus blinded LLM review against the
frozen functional contract. It is not a substitute for executable tests. The
Security Oracle is independent and preserves `unknown`; unknown is never
promoted to secure.

The completed Qwen3.5 and Qwen3.7 strict-TSG studies are frozen null results on
the same 19-task-unit census. Their reports remain evidence of that bounded
population, not a universal no-effect claim:

- `docs/experiments/2026-08-26-prompt-tsg-strict-v2-results.md`;
- `docs/experiments/2026-08-26-prompt-tsg-qwen37-oracle-v3-results.md`.

## Reviewer commands

Run the focused scientific-invariant suite:

```text
python -m pytest -q
```

Run the zero-provider-call preflight for the active pairwise confirmation:

```text
prompt-mechanism-study factorial-experiment preflight \
  .artifacts/factorial-confirm-preflight \
  --repository-root . \
  --config configs/formal/factorial-sql-confirm-qwen35-v3.json
```

With the externally supplied provider credential, run the same frozen path:

```text
prompt-mechanism-study factorial-experiment run \
  .artifacts/factorial-sql-confirm-qwen35-v3 \
  --repository-root . \
  --config configs/formal/factorial-sql-confirm-qwen35-v3.json
```

The run command writes the complete assignment ledger, factorial estimates,
unknown bounds, preregistered secondary intervals, and the independent-verifier
result into one content-addressed bundle. Claim permission does not imply a
positive or significant result; the frozen primary and practical gates still
apply.

Verify the tracked formal v3 result bundle and its frozen file hashes:

```text
prompt-mechanism-study verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3
```

Verify the tracked Qwen3.7 analysis independently:

```text
prompt-mechanism-four-arm verify-analysis \
  data/formal/results/prompt-tsg-strict-19-qwen37-oracle-v3-analysis \
  --config configs/formal/prompt-tsg-strict-19-qwen37-oracle-v3.json \
  --tasks data/formal/prompt-tsg-strict-v3-replication-tasks.jsonl
```

The older four-arm entry point exposes reproduction actions for tracked
legacy/pilot studies only. New pairwise work uses `factorial-experiment` and
must not reuse a legacy result under successor semantics. Provider credentials
and model deployment remain external adapters; they are not stored in the
artifact.

## Review reading order

The active path can be reviewed in at most ten files:

1. `AGENTS.md` -- scientific and reviewability constraints;
2. `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`
   -- normative protocol, including the pairwise extension;
3. `configs/formal/factorial-sql-confirm-qwen35-v3.json` -- complete prospective
   confirmation identity and evidence boundary;
4. `src/prompt_mechanism_study/prompt_tsg.py` -- bounded Prompt-TSG schema;
5. `src/prompt_mechanism_study/mechanisms.py` -- atomic features, `PairSpec`,
   and outcome-blind binding;
6. `src/prompt_mechanism_study/intervention.py` -- four-cell bundled policy;
7. `src/prompt_mechanism_study/randomization.py` -- replayable complete blocks;
8. `src/prompt_mechanism_study/factorial_experiment.py` -- single linear run
   path and total ledger;
9. `src/prompt_mechanism_study/inference.py` -- task-unit ITT, bounds, and
   simultaneous inference;
10. `src/prompt_mechanism_study/factorial_verify.py` -- independent result
    verifier;

Historical ADD/REMOVE studies, deployment incidents, provider tuning,
calibration exploration, and server administration remain archival evidence.
They are not alternative active execution paths.
