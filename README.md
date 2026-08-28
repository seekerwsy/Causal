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

The prospective extension tests two independently editable atomic Prompt
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

Active schema 1.1 inference draws once from the frozen union of task units and
moves every supported pair/model descendant together. Each multiplicity family
uses replicate-specific studentization and a frozen max-|T| upper empirical
quantile. Partially overlapping pair supports are retained; a replicate is
invalid only when a tested coordinate falls below its frozen minimum support or
has zero replicate standard error. The run must meet its frozen minimum valid
replicate fraction, otherwise that interval family is reported non-evaluable.

The security-interaction gate and the practical-success gate are distinct. A
functionality non-inferiority claim is evaluated only when it was separately
powered before outcomes and the simultaneous lower bound for `A11 - A00` is at
least the negative frozen margin. Otherwise functionality is reported as
`not_requested` or `not_evaluable`; a favorable point estimate cannot silently
authorize a practical-success claim.

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

A separately frozen prospective follow-up retained the same 30 task units but gave
each task a new prompt identity containing a deterministic starter implementation in
which both controls were absent. It completed another 240 assignments. Secure yield
was 0.0% in A00, 11.7% in A10, 16.7% in A01, and 98.3% in A11. The primary interaction
was +70.0 percentage points with a simultaneous interval of `[+56.7, +83.3]`, and the
functionality non-inferiority gate passed. This supports a bounded scaffold-repair
prompt-policy effect, not universal mechanism synergy or a randomized causal effect of
scaffold context. See
`docs/experiments/2026-08-27-factorial-sql-scaffold-repair-v1-results.md`.

The current implementation also closes the prospective atomic ADD/REMOVE
four-arm runner, all five shared-universe selectors, the selector-invariant
bridge, the Prompt-TSG pair selector, and generalized multi-pair/multi-model
factorial dispatch. These paths have independent semantic replay or result
verification. They are implementation and test evidence only until a new study
is prospectively frozen and run against the declared provider models.

RQ2 representation comparison is implemented as a replay over two already
complete selector-result funnels: one direct representation and one
direct-plus-context representation. It checks both source bundles and
recomputes candidate coverage, protocolization, ConfirmedYield@K, and effect
summaries. Because representation changes the candidate universe as well as
selection, this is an end-to-end representation comparison, not a pure
selector-effect estimate.

The prospective selector boundary is schema 2.0 only; schema 1.0 can be opened
only through explicitly named `archival-*` phases. Pair selection embeds the
representative task text and Prompt-TSG graph and recomputes every relation
motif rather than trusting supplied node IDs. Successor and schema-1.1
factorial result verifiers also replay the frozen provider responses into code,
syntax/compilation, Security Oracle, Functional Judge, Measurement, ledger, and
reported estimates without making another provider call. Schema-1.0 factorial
bundles retain their historical verifier boundary and are not reinterpreted.

## Outcomes and evidence boundary

The primary safety outcome is observed Oracle-evaluable secure-code yield.
Code validity, Oracle evaluability, unknown coverage, functionality, and
secure-and-functional joint success remain separate fields.

The Functional Judge is AST/compilation plus blinded LLM review against the
frozen functional contract. It is not a substitute for executable tests. The
Security Oracle is independent and preserves `unknown`; unknown is never
promoted to secure.

Active successor and schema-1.1 factorial freezes require the same ordered five
endpoints: secure yield, code validity, Oracle evaluability, functionality, and
joint secure-and-functional success. Oracle unknown is assessed among valid code;
an arm or cell with no valid code is non-evaluable rather than assigned a favorable
coverage value. A claim-bearing functionality non-inferiority Gate additionally
requires a study-specific, pre-outcome power qualification sealed into the freeze.

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

Run the smallest structural reproductions after a method-level change:

```text
python -m pytest -q -m milestone
```

The dedicated schema-1.1 reviewer smoke is also runnable alone:

```text
python -m pytest -q -m milestone tests/test_factorial_reviewer_smoke.py
```

It closes `2 task units x 1 pair x 2 orders x 4 cells x 1 model = 16`
assignments through freeze, run, and independent verification. Provider
transport is a strict offline fixture, while the tracked local Security Oracle
is executed and its existing gold cases are replayed. The generated result is
temporary, `scientific_claim_allowed` is false, functionality is not separately
powered, and no smoke estimate is effect evidence. Its Functional Judge fixture
has status `STRUCTURAL_SMOKE_ONLY`; the loader rejects that status outside a
non-claiming development canary.

The package installs one console entry, `prompt-mechanism-study`. Its
prospective subcommands expose one method through explicit stage boundaries:

```text
prompt-mechanism-study selector-study --help
prompt-mechanism-study successor-experiment --help
prompt-mechanism-study interaction-selector --help
prompt-mechanism-study factorial-experiment --help
```

Replay an RQ2 representation comparison from two complete selector-result
bundles, or independently verify the stored comparison:

```text
prompt-mechanism-study selector-study compare-representations OUTPUT --config CONFIG
prompt-mechanism-study selector-study verify-representations OUTPUT
```

Each stored selector, bridge, successor result, pair selection, and factorial
result has a semantic verifier; exact-byte `verify` alone is not used as proof
that a scientific result was recomputed.

An active schema-1.1 factorial study must be materialized before generation:

```text
prompt-mechanism-study factorial-experiment freeze FREEZE \
  --repository-root . \
  --config ACTIVE_SCHEMA_1_1_CONFIG

prompt-mechanism-study factorial-experiment run RESULT \
  --repository-root . \
  --config ACTIVE_SCHEMA_1_1_CONFIG \
  --freeze FREEZE
```

The tracked scaffold-repair configuration is schema 1.0 evidence. Its
zero-provider-call preflight therefore uses the explicit archival phase:

```text
prompt-mechanism-study factorial-experiment archival-preflight \
  .artifacts/factorial-scaffold-repair-preflight \
  --repository-root . \
  --config configs/formal/factorial-sql-scaffold-repair-qwen35-v1.json
```

With the externally supplied provider credential, its historical execution
path remains reproducible but cannot create successor evidence:

```text
prompt-mechanism-study factorial-experiment archival-run \
  .artifacts/factorial-sql-scaffold-repair-qwen35-v1 \
  --repository-root . \
  --config configs/formal/factorial-sql-scaffold-repair-qwen35-v1.json
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

Independently rederive its assignment bindings, outcomes, task-unit estimates,
unknown bounds, and bootstrap intervals from the stored measurement ledger:

```text
prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3
```

Verify the tracked scaffold-repair follow-up bundle:

```text
prompt-mechanism-study verify \
  data/formal/results/factorial-sql-scaffold-repair-qwen35-v1
```

Recompute the follow-up result rather than trusting its stored analysis:

```text
prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-scaffold-repair-qwen35-v1
```

Verify the tracked Qwen3.7 analysis independently:

```text
python -m prompt_mechanism_study.four_arm_cli verify-analysis \
  data/formal/results/prompt-tsg-strict-19-qwen37-oracle-v3-analysis \
  --config configs/formal/prompt-tsg-strict-19-qwen37-oracle-v3.json \
  --tasks data/formal/prompt-tsg-strict-v3-replication-tasks.jsonl
```

The legacy four-arm runner is deliberately available only as an explicit
Python module, not as a second installed console command. The main CLI exposes
older kernel and two-arm paths only through command names that start with
`archival-`. New work uses the successor stages and must not reuse a legacy
result under successor semantics. Provider credentials and model deployment
remain external adapters; they are not stored in the artifact.

## Review reading order

The scientific core can be reviewed in at most ten files:

1. `AGENTS.md` -- scientific and reviewability constraints;
2. `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`
   -- normative protocol;
3. `src/prompt_mechanism_study/prompt_tsg.py` -- bounded Prompt-TSG schema;
4. `src/prompt_mechanism_study/mechanisms.py` -- atomic and pair semantics;
5. `src/prompt_mechanism_study/prioritization.py` -- support gates and selectors;
6. `src/prompt_mechanism_study/intervention.py` -- frozen four-arm/four-cell policy;
7. `src/prompt_mechanism_study/randomization.py` -- replayable complete blocks;
8. `src/prompt_mechanism_study/measurement.py` -- independent measurements;
9. `src/prompt_mechanism_study/inference.py` -- task-unit ITT and simultaneous inference;
10. `src/prompt_mechanism_study/workflow.py` -- seven-stage composition.

See `docs/reviewer-guide.md` for the thin runner and independent-verifier
boundaries. The tracked formal configs and results reproduce executed evidence;
they are not implementation definitions.

Historical ADD/REMOVE studies, deployment incidents, provider tuning,
calibration exploration, and server administration remain archival evidence.
They are not alternative active execution paths.
