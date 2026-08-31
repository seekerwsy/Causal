# Reviewer guide

This repository has one normative successor method, currently at
`SPECIFIED_DRAFT`. It is not yet authorized for formal discovery or
confirmation. The installed `prompt-mechanism-study` command still exposes the
reviewable pre-cutover selector, successor, and factorial stage implementations;
those are migration/legacy execution boundaries, not competing normative
frameworks and not evidence for the unfinished target protocol.

The normative protocol is the
[context-conditioned intervention policy framework](superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).
The draft target uses the prospective `phase-context-policy-v3` / `3.x` schema
family. Existing selector schema 2.1, successor schema 2.x, and factorial schema
1.x retain their exact historical or migration interpretation. Immutable
historical result bundles remain available to their independent result
verifiers, but target report builders must reject them after cutover.

The review tree retains the active specification, current dataset-curation
records, Functional Judge qualification inputs, the two replayable factorial
result bundles, and their result notes. Superseded E2E deployments, server
runbooks, predecessor four-arm studies, implementation plans, and incident
chronology were removed from the live tree after commit `f94d109`; Git history
is their recovery boundary.

## Seven-stage artifact path

| Stage | Frozen input | Output | Main implementation |
| --- | --- | --- | --- |
| Representation | normalized source records, five-role manifest, and Prompt TSG catalog | deduplicated task units, canonical scope/policy identity, Prompt TSG and control bindings | `representation.py`, `mechanisms.py` |
| Prioritization | DISCOVERY task units plus accepted Atomic/Pair/baseline profiles | sole-difference Full/Ablation and qualified optional baseline fixed slots | `prioritization.py`, `interaction_selector.py`, `rq1_baselines.py` |
| Hypothesis freeze | accepted qualification, budget, fixed slots, unique union and bridge/protocolization | two correctly timed freezes, model-bound dispatch, tasks, realizations, assignments, and ITT plan | `study_design.py`, `prioritization.py` |
| Intervention/randomization | frozen model-effect coordinates and task-policy bundles | complete assigned-arm blocks with unique request-randomness slots | `intervention.py`, `randomization.py` |
| Measurement | assigned prompt plus frozen adapters | raw responses, code validity, Security Oracle result, Functional Judge result | `measurement.py` |
| Outcome assembly | every randomized assignment and measurement | total assigned-arm evidence ledger with outcome-or-infrastructure-failure partition | `outcomes.py`, `inference.py` |
| Inference/reporting | frozen ITT plan, total ledger, and study-freeze index | separate Atomic/Pair max-\|T\| families, five statuses, fixed-K RQ tables, and formal report authorization | `inference.py`, `selector_analysis.py`, `selector_verify.py` |

The target implementation is a transparent sequence of typed stage functions,
not a configurable orchestration framework. Shared exact-JSON, hashing,
path-confinement, and bundle operations live in `artifact_io.py`. Qualification,
power/budget, both timed freezes, preflight, and claim authorization live in
`study_design.py`. Target result verification does not reuse the production
estimator or table builder. `target-study verify-result` is the sole read-only
schema-3.0 package boundary and rejects any package that omits or substitutes
the target role, freeze, assignment, evidence, authorization, table, or receipt
records. The formal execution CLI cutover remains disabled until the
prospective role manifest and numeric qualification artifacts are accepted.

## Scientific invariants

A review should confirm all of the following:

- Prompt TSG edges encode prompt semantics, never causal structure.
- Generated code supplies independently measured security and functionality
  outcomes; it is not a mediator or primary-PAG variable.
- Formal design, role/profile references, folds, selector definitions, and
  budget are sealed in `DiscoveryDesignFreeze` before discovery outcomes.
  Fixed slots, their unique union, shared bridge/task/realization records, the
  deterministic randomization plan, assignments, estimands, and reporting rules are then sealed in
  `ConfirmationFreeze` before confirmation outcomes.
- A semantic `policy_key` is model-independent; each scientific effect is
  `(policy_key, model_id)`, and model-bound records cannot be crossed over the
  model list a second time.
- `QUAL_DEV`, one-shot unexposed `QUAL_ACCEPT`, `DISCOVERY`, `CONFIRMATION`, and
  `LEGACY_ONLY` task units and near-duplicate groups are separated by one
  content-addressed role manifest. DevEval v4 is historical and cannot be
  rebound to current source or target qualification.
- Atomic and pair discovery states are recomputed from the embedded catalog,
  prompt, and Prompt TSG evidence; a producer-supplied binary state is never
  accepted as representation evidence by itself.
- ADD and REMOVE use operation-specific target/control coding. In the target
  method, independent compatibility defines the common Pair universe; only
  Pair Full reads relation support, while No-Relation does not.
- Optional blinded Expert and seeded Random selectors consume that same
  support-qualified, model-bound universe and `K`. Expert cards cannot read
  RD/FCI/relation/selector or target-outcome fields; Random uses one frozen
  SHA-256 ordering seed. Both emit ordinary fixed-slot sources and therefore
  share the union, bridge, confirmation, status, and accounting path.
- Every task-unit/realization/model block has complete assigned-arm support.
- One semantic policy has one protocolization and one task-policy bundle per task;
  model-specific effect records reuse those bytes, while the verifier independently
  reconstructs each complete-block arm order, variant digest, and provider seed.
- RQ2 is the descriptive fixed-denominator Full-minus-Ablation Yield difference;
  the target freeze rejects rank pairing and continuous selector-utility intervals.
- Assigned-arm, deduplicated-task-unit ITT is primary; task units are equally
  weighted.
- Fidelity, semantic compliance, generation success, and non-target drift are
  diagnostics and never denominator filters.
- Invalid code, Security Oracle `unknown`, functional failure, and terminal
  model output remain in the assignment ledger under their frozen semantics.
- Secure-code yield is separate from validity, evaluability, unknown coverage,
  functionality, and joint success.
- A functionality non-inferiority claim requires a pre-outcome study-specific
  power qualification; a favorable point estimate alone cannot authorize it.
- Smoke, demo, calibration, and development-canary outputs cannot be promoted
  to confirmatory evidence.
- A statistically nonadditive pair is first a Prompt-policy response-surface
  result. A mechanism-interaction label additionally requires a prospectively
  frozen `mechanism_eligible` Oracle scope; `policy_only` cannot be promoted by
  significance.

## Reading order

The target scientific core can be reviewed in ten files:

1. `docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md`
2. `src/prompt_mechanism_study/representation.py`
3. `src/prompt_mechanism_study/mechanisms.py`
4. `src/prompt_mechanism_study/prioritization.py`
5. `src/prompt_mechanism_study/interaction_selector.py`
6. `src/prompt_mechanism_study/study_design.py`
7. `src/prompt_mechanism_study/rq1_baselines.py`
8. `src/prompt_mechanism_study/inference.py`
9. `src/prompt_mechanism_study/selector_analysis.py`
10. `src/prompt_mechanism_study/selector_verify.py`

For historical-bundle verification only, then read the matching legacy pair:
`successor_experiment.py`/`successor_verify.py` or
`factorial_experiment.py`/`factorial_verify.py`. Those modules do not define the
target v3 method.

## Reproduction commands

Run the target reviewer-facing invariant suite:

```text
.venv\Scripts\python.exe -m pytest -m reviewer -q
```

The current expected result is 65 passing tests. Run the complete retained
repository suite separately:

```text
.venv\Scripts\python.exe -m pytest -q -o addopts=""
```

The current expected result is 183 passing tests. The smallest zero-network
target-method closure is:

```text
.venv\Scripts\python.exe -m pytest -q -o addopts="" \
  tests/test_study_design.py::test_target_two_freeze_lineage_closes_and_independently_replays
```

This synthetic fixture closes accepted-profile lineage, budget, fixed slots,
unique dispatch, balanced assigned arms, both timed freezes, task-unit ITT,
exact on-disk package writing, read-only CLI verification, independent
scientific replay, and the report-authorization boundary. Its authorization
object and temporary bundle are implementation checks only; they are not a
formal run or scientific evidence.

Verify an actual target package after one exists:

```text
prompt-mechanism-study target-study verify-result TARGET_SCHEMA_3_RESULT
```

The verifier requires the exact target file set and reconstructs all typed
records before replaying shared policy protocolization/task bundles, the frozen
randomization plan, exact four-arm order and variant/provider-seed binding,
budget, both freezes, assigned-arm ITT, max-\|T\| families, five statuses,
fixed-K Yield, claim authorization, and
RQ tables. It never starts provider calls. At the current `SPECIFIED_DRAFT`
checkpoint there is no tracked target package to pass to this command. A
future reviewer distribution must also carry every raw response, measurement,
frozen-input, environment, command, and provider-ledger artifact referenced by
the result index; the index does not make those external records optional.

Verify a tracked frozen result at both artifact and scientific levels:

```text
prompt-mechanism-study verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3

prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3
```

The second command independently replays stored provider responses through
code extraction, syntax/compilation, Security Oracle, Functional Judge,
measurement, total-ledger assembly, and inference without another provider
call. The scaffold-repair reference bundle can be substituted in the same
commands.

The following pre-cutover factorial command remains available only under its
own historical/migration contract; it is not the target v3 entry point:

```text
prompt-mechanism-study factorial-experiment preflight PREFLIGHT \
  --repository-root . --config ACTIVE_SCHEMA_1_1_CONFIG

prompt-mechanism-study factorial-experiment freeze FREEZE \
  --repository-root . --config ACTIVE_SCHEMA_1_1_CONFIG

prompt-mechanism-study factorial-experiment run RESULT \
  --repository-root . --config ACTIVE_SCHEMA_1_1_CONFIG --freeze FREEZE
```

Provider credentials and deployments are external. The reviewer artifact does
not include server administration, retries, recovery machinery, calibration
exploration, or temporary checkpoints.

## Current evidence status

The target method remains `SPECIFIED_DRAFT`, but its method core is now
implemented and reviewer-tested: five data roles and near-duplicate firewall;
model-independent Atomic/Pair policy identity; Atomic Full/RD-only; Pair
  Full/No-Relation with four Prompt-TSG predicates; optional blinded Expert and
  seeded Random target selectors with shared-universe fixed slots and independent
  ranking replay; fixed K slots; unique
  model-effect union and model-bound dispatch; shared task-policy bundles;
  deterministic complete-block randomization; assigned-arm task-unit ITT; separate Atomic
and Pair max-\|T\| families; five statuses; assumption-conditional power;
joint provider budget/preflight; two timed freezes; RQ1/RQ2 tables; and formal
report authorization with independent replay. This is `implemented/tested`,
not `executed` or `reported`.

Formal activation is blocked for substantive, prospective reasons rather than
missing method-core code. The outcome-blind census leaves 141 unexposed ready
task units after excluding 23 exact legacy overlaps, below the current
240-task population target. Resolving every pending binding would raise the
ready count, while qualifying all current-scope measurement gaps gives an
exact-unexposed ceiling of 318: 159 pending Oracle, 16 pending binding, and two
pending independent-review units beyond the current 141. The equal family
ceilings are nevertheless 128/91/43/56, so retaining 60 per family requires at
least 17 new identity and four new cryptography units before near-duplicate
reserve. No author-approved margins, power grid, K values,
model set, task/realization/slot counts, rates, or ceilings have been accepted;
therefore no QUAL_DEV/one-shot QUAL_ACCEPT/DISCOVERY/CONFIRMATION allocation,
accepted qualification bundle, formal freeze artifact, provider execution, or
claim-bearing report exists.
The exact fields requiring one joint author decision are collected, without
defaults or execution authorization, in
`docs/superpowers/phase0/parameter_qualification_register.md` under
“Single author decision gate.”
Scope contraction does not remove required comparisons. Atomic Full/RD-only
and Pair Full/No-Relation are the mandatory Core and are implemented/tested.
Blinded Expert and seeded Random are now executable schema-3 selectors for both
tracks: their information/seed provenance, candidate permutation, model
dispatch, fixed slots, shared union, and independent replay are tested. The
budget additionally requires an accepted baseline qualification for every
selected selector/model coordinate; a scenario name alone cannot pass. The
author must still choose the exact RQ1 envelope and complete the prospective
baseline cards/seeds and one-shot qualification. Association/Prediction remain
legacy-schema implementations and cannot enter the target RQ1 set without a
separately approved target contract.
The target budget implementation does not accept an opaque manual per-call
price: every materialization, generation, and functional-judge rate must derive
from one frozen currency/region/tier, input/output token ceilings, per-million
token prices, and a content-addressed pricing reference; the independent
verifier recomputes the rounded microunit bound.

The three named v5 populations contain 69 unique exposed task units and remain
`LEGACY_ONLY`. Their two unique provider request/response bundles have
byte-identical, exact-manifest repository archive copies under
`data/method/archive/legacy-v5`; a stable `legacy-v5-role-bindings-v2` input now
feeds the active `phase-context-policy-v3-role-census-v6` without a circular
output hash. These copies are included in the current implementation checkpoint;
the ignored runtime originals remain only as recoverable development history.

The successor, schema-2.1 selector, pair selector, and generalized schema-1.1
factorial paths are implemented and reviewer-tested. Fresh seven-source
semantic curation and all functional contracts are complete. The active
outcome-blind candidate-data audit gives every one of the 2,165 task units a
typed disposition: 1,229 contracts pass the strict review rule and 164 Python
task units currently satisfy all confirmatory data gates. The 240-task Python
population gate remains closed. The C/C++ and 28-scenario BaxBench data
inventories are complete, but their executable runtimes remain unqualified.
The closed inputs, result hashes, Oracle profile inventory, and protocol risks
are recorded in
[`2026-08-31-final-candidate-data-audit.md`](experiments/2026-08-31-final-candidate-data-audit.md).

The active
task-level Prompt TSG contract bounds both LLM annotators to the complete
catalog-v11 task scope, keeps exact prompt evidence, and deterministically
preserves disagreement as unresolved. Its prospectively frozen v10 DevEval
qualification completed 28/28 graphs and 56 calls with four task workers in
506.63 seconds, but failed Gate C at 24/28 exact, 7/10 present recall, one
false-positive present state, and one wrong realization. The transport,
completeness, and bounded scheduler therefore close; caller/external-input
semantics and independently fixed executable identity remain unqualified. The
failed result is not retried or relabelled. Formal discovery and confirmation
did not start. All 28 task units are conservatively disclosed as previously
provider-exposed by aborted, unscored transport/scheduling attempts; no prior
semantic response bundle or gold comparison was retained or inspected.
The exact evidence inventory and failed-Gate boundary are in
[`gate-e-readiness.md`](gate-e-readiness.md). The tracked schema-1.0 factorial
results are formal historical evidence and remain reproducible through the
verifier, but are not reinterpreted under schema 1.1. Passing a test establishes
neither execution nor an effect.
