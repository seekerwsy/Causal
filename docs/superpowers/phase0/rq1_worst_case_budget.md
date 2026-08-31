# RQ1 Worst-Case Selection and Confirmation Budget

**Status:** `NON_NORMATIVE_PHASE_0_BUDGET_MODEL`

**Normative target:**
[`../specs/2026-08-20-context-conditioned-intervention-policy-framework.md`](../specs/2026-08-20-context-conditioned-intervention-policy-framework.md)

No numeric RQ1 budget is currently qualified. This document defines the accounting identities that
must be evaluated before `K_A`, `K_I`, baseline selectors, models, task units, realizations, or block
slots are frozen. It does not authorize provider calls.

The executable formula is `study_design.py::rq1_worst_case_budget_envelopes`. Its output remains
`SPECIFIED_DRAFT`, sets `provider_calls_authorized=false`, and rejects any request to cross
model-bound candidate records over the model set again. Synthetic arithmetic tests validate the
three scenario multipliers; they are not a numeric study budget or power result.

## Resolved identity and dispatch decision

**Decision recorded 2026-08-31:** the semantic `policy_key` is model-independent; a scientific
effect is `(policy_key, model_id)`; and a Stage-II candidate record is bound to exactly one discovery
model and dispatched only to that same confirmation model. An explicit policy-lineage map may
deduplicate bridge/materialization across model-effect records.

The rejected alternative is to take model-bound records and pass each through the current
all-policy-by-all-model loop. That would count the model dimension twice and create a different
scientific design, not merely a larger bill. The target preflight must reject it.

This closes the identity-rule decision but does not freeze any numeric budget. Exact models,
`K_A`, `K_I`, tasks, realizations, block slots, prices, margins, and the selected RQ1 scenario remain
`AUTHOR_INPUT_NEEDED` or qualification-blocked.

## Symbols

| Symbol | Meaning |
|---|---|
| `S_A`, `S_I` | Number of active Atomic and Pair selector variants included in RQ1. |
| `M` | Number of model-specific selection/effect strata. Use per-track `M_A`, `M_I` if different. |
| `K_A`, `K_I` | Frozen slots per Atomic/Pair selector variant and model stratum. Empty slots remain in these denominators. |
| `U_A`, `U_I` | Unique nonempty selected Atomic/Pair **effect-coordinate records** after union and deduplication. |
| `P_A`, `P_I` | Unique model-invariant intervention policies after bridge/policy deduplication, if that layer is approved. |
| `T_A(h)`, `T_I(p)` | Number of confirmation task units assigned to Atomic record `h` or Pair record `p`. |
| `R_A(h)`, `R_I(p)` | Number of global realizations in the frozen policy distribution. These affect task allocation and power, not a multiplicative per-task request loop. |
| `r(h,t)` | The one outcome-blind realization assigned to task unit `t` for policy `h`; every task-policy coordinate has exactly one. |
| `Q_A`, `Q_I` | Total assignment slots in one Atomic/Pair task-unit × candidate × assigned-realization × model block. Both are multiples of four and already include all four arms/cells. |
| `B_A`, `B_I` | Unique task-policy bundles requiring materialization after the one-realization allocation. |
| `N_gen` | Total model generation assignments/provider calls. |
| `N_func` | External functional-judge calls. Security Oracle evaluation is local and is not included as a provider call. |

`Q_A` and `Q_I` are total block slots, not replicates per arm. If the design instead starts from `q`
replicates per arm/cell, set `Q = 4q`; never multiply a total-slot input by four again.

## Selection-union bounds

With model-bound effect records and no overlap between selector slots, the worst-case unions are:

\[
U_A \le S_A M K_A, \qquad U_I \le S_I M K_I.
\]

Overlap, typed empty slots, scoring failures, or bridge failures reduce the actual unique union, but
must not reduce the prespecified `Yield@K` denominators or trigger replacement selection.

| RQ1 scenario | Atomic variants (`S_A`) | Pair variants (`S_I`) | Worst-case `U_A` | Worst-case `U_I` | Method status |
|---|---:|---:|---:|---:|---|
| Core | Full + RD-only = 2 | Full + No-Relation = 2 | `2 M K_A` | `2 M K_I` | Required target comparison |
| Core + one expert baseline | 3 | 3 | `3 M K_A` | `3 M K_I` | Optional; only if expert protocols exist for both tracks and fit budget |
| Core + expert + random | 4 | 4 | `4 M K_A` | `4 M K_I` | Optional maximum comparison set |

The table is a budget envelope, not approval of Pair expert/random selectors. If baseline sets differ
by track, use the general `S_A`/`S_I` formulas rather than forcing equal counts.

It is also not implementation evidence. Selecting an envelope requires every named baseline to emit
target-schema fixed slots under a frozen ranking/blindness contract and to pass the same bridge,
confirmation, status, accounting, and independent-verifier boundaries as Core. The current
Expert/Random names in budget code reserve capacity only. Legacy Association/Prediction code may
enter only through an explicit target definition and qualification; it cannot be silently promoted.

## Exact assignment identity

Under model-bound dispatch, where each record is evaluated only at its bound model coordinate:

\[
N_{gen}
=
Q_A \sum_{h\in U_A}T_A(h)
+
Q_I \sum_{p\in U_I}T_I(p).
\]

For uniform per-track task counts this becomes:

\[
N_{gen}
= U_A T_A Q_A + U_I T_I Q_I.
\]

Combining that expression with the no-overlap selector bound gives:

\[
N_{gen}
\le
S_A M K_A T_A Q_A
+
S_I M K_I T_I Q_I.
\]

For a scenario with the same number `c` of variants on both tracks:

\[
N_{gen}
\le
cM\left(K_A T_A Q_A + K_I T_I Q_I\right),
\quad c\in\{2,3,4\}.
\]

`R_A` and `R_I` remain frozen scientific coordinates. The allocation must place enough independent
task units in every realization stratum for the planned robustness analysis, but no task is run once
per global realization.

## Accidental model-square failure mode

If the selected union already contains `M` model-specific records per selector slot and the current
runner again cross-products each record with all `M` configured models, the upper bound becomes:

\[
N_{gen}^{\text{wrong}}
\le
S_A M^2 K_A T_A Q_A
+
S_I M^2 K_I T_I Q_I.
\]

The target preflight must reject this configuration, even when it remains under a financial cap,
because it changes the intended effect coordinates as well as cost.

## Policy materialization calls

One current task-realization bundle materialization uses one executor call and one validator call and
returns all four Atomic variants or all four Pair cells. Let:

\[
B_A = \sum_{a\in P_A}T_A(a),
\qquad
B_I = \sum_{i\in P_I}T_I(i).
\]

Then the maximum materialization-provider calls are:

\[
N_{materialize}=2(B_A+B_I).
\]

If no model-invariant policy key is approved, conservatively set `P_A = U_A` and `P_I = U_I`. If
policy deduplication is approved, the budget artifact must show the exact effect-record-to-policy map;
it may not infer reuse from equal prompt text after freezing.

## Generation, judging, and total external calls

- One assignment requires at most one model-generation provider call, so generation calls equal
  `N_gen`.
- A functional judge can be called at most once per assignment reaching functional evaluation, so
  `N_func <= N_gen`. The worst case sets `N_func = N_gen`.
- The Security Oracle is local. Oracle unsupported/unknown outcomes remain recorded but add no
  provider call in this accounting model.

Therefore the conservative external-call ceiling is:

\[
N_{external}^{max}=2(B_A+B_I)+2N_{gen}.
\]

Any other external review, retry, or adjudication service must receive its own term and frozen retry
limit. It must not be hidden inside a generic contingency multiplier.

## Scenario worksheet

| Scenario | Unique-effect upper bound | Generation-call upper bound | External-call upper bound |
|---|---|---|---|
| Core (`c=2`) | `U_A <= 2MK_A`, `U_I <= 2MK_I` | `2M(K_A T_A Q_A + K_I T_I Q_I)` | `2(B_A+B_I) + 2N_gen` |
| Core + expert (`c=3`) | `U_A <= 3MK_A`, `U_I <= 3MK_I` | `3M(K_A T_A Q_A + K_I T_I Q_I)` | `2(B_A+B_I) + 2N_gen` |
| Core + expert + random (`c=4`) | `U_A <= 4MK_A`, `U_I <= 4MK_I` | `4M(K_A T_A Q_A + K_I T_I Q_I)` | `2(B_A+B_I) + 2N_gen` |

These bounds assume the same `M`, `T`, and `Q` within each track only for readability. The
machine preflight must use exact per-record coordinates and also report the symbolic worst case.

## Costs that do not disappear when execution fails

- Empty selection slots cost no confirmation calls but remain zero-contribution slots in yield.
- Bridge/protocolization failure can prevent assignments and calls, but cannot free the slot for a
  replacement candidate.
- Generation/backend failure still consumes any attempted provider call and remains an assigned-arm
  outcome.
- Functional non-evaluability may reduce actual judge calls, but the worst-case reservation must keep
  one judge call per assignment.
- Duplicate selection by several variants reduces unique confirmation cost only through the frozen
  union/candidate-to-slots map; it does not reduce any variant's `K` denominator.

## Outcome-blind author-decision sensitivity (not a freeze)

The following 2026-08-31 calculation narrows the remaining author decision. It is a deterministic
use of `study_design.simulate_target_power` in the repository Python 3.12 environment. It reads no
target discovery or confirmation outcome, authorizes no provider call, and is not a
`power_and_margin_memo.json`.

The sensitivity scenario fixes baseline oracle-evaluable secure-code yield at 0.30, Oracle-unknown
and terminal-no-code rates at 0.10 each, within-arm request ICC at 0, cross-arm task correlation at
0.30, realization-effect SD at 0.05, family-coordinate correlation at 0.20, two global
realizations with one realization assigned per task, two request slots per arm, two-sided alpha
0.05, practical margin 0.05, target power 0.80, and 10,000 deterministic simulation replicates.
Atomic and Pair effects below are assumption values, not observed effects or promises about the
formal study.

| Track | Fixed K | True effect assumption | Power at 60 tasks | 100 tasks | 120 tasks | 170 tasks | 190 tasks | 240 tasks |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Atomic | 5 | 0.20 | 0.540 | 0.824 | 0.902 | 0.981 | 0.990 | 0.998 |
| Atomic | 5 | 0.25 | 0.852 | 0.986 | 0.996 | 1.000 | 1.000 | 1.000 |
| Atomic | 10 | 0.20 | 0.437 | 0.752 | 0.851 | 0.965 | 0.984 | 0.998 |
| Atomic | 10 | 0.25 | 0.797 | 0.975 | 0.991 | 1.000 | 1.000 | 1.000 |
| Pair | 3 | 0.20 | 0.292 | 0.521 | 0.625 | 0.811 | 0.859 | 0.935 |
| Pair | 3 | 0.25 | 0.564 | 0.834 | 0.906 | 0.982 | 0.990 | 0.998 |
| Pair | 5 | 0.20 | 0.242 | 0.460 | 0.561 | 0.757 | 0.817 | 0.914 |
| Pair | 5 | 0.25 | 0.495 | 0.786 | 0.874 | 0.969 | 0.984 | 0.997 |

With one request slot rather than two, the same implementation gives materially lower power. For
example, at 120 tasks and a true effect of 0.20, power is 0.543 for Atomic `K=5`, 0.453 for Atomic
`K=10`, 0.297 for Pair `K=3`, and 0.238 for Pair `K=5`. Repeated slots do not create independent
task units, but the sensitivity shows why one slot cannot be assumed adequate before the accepted
power grid exists.

The current 141-task unexposed census is a total pool that must be split across `QUAL_DEV`, one-shot
`QUAL_ACCEPT`, `DISCOVERY`, and `CONFIRMATION`; it is not 141 confirmation tasks per hypothesis.
Consequently this calculation does not support adopting the 141-unit pool as the default formal
population. The conservative planning path is to retain the 240-task coverage target, qualify an
exact role allocation and hypothesis-specific eligible-task counts, and acquire more unexposed
units if the accepted Pair grid requires them.

The complete current-scope ledger has 346 quality-qualified Python task units and an exact-unexposed
ceiling of 318 after 28 legacy overlaps. Beyond the 141 ready units, 159 need Oracle support, 16
need a binding, and two need independent review. Existing-corpus implementation work can therefore
reach a 240 total without importing the separate priority-extension CWEs. It cannot satisfy the
current equal-family target by itself: exact-unexposed family ceilings are 128
injection/interpreter, 91 file/parser/resource, 43 identity/authorization/permission, and 56
cryptography/randomness/integrity. A 60/60/60/60 freeze needs at least 17 new identity-family and
four new cryptography-family task units, plus reserve for later near-duplicate exclusions. An
unequal-family amendment could avoid that acquisition, but would change the target population and
must be decided prospectively rather than inferred from these counts.

For one model, Core selectors, two request slots per arm, and no overlap credit, the implemented
budget function gives these exact call ceilings:

| `K_A` | `K_I` | Tasks per Atomic/Pair effect | Materialization | Generation | Functional judge | Total external calls |
|---:|---:|---:|---:|---:|---:|---:|
| 5 | 3 | 120 | 3,840 | 15,360 | 15,360 | 34,560 |
| 10 | 5 | 120 | 7,200 | 28,800 | 28,800 | 64,800 |
| 5 | 3 | 170 | 5,440 | 21,760 | 21,760 | 48,960 |
| 10 | 5 | 190 | 11,400 | 45,600 | 45,600 | 102,600 |

The repository's current Beijing pay-as-you-go candidates are
`qwen3.5-flash-2026-02-23` for generation and `qwen3.7-max-2026-05-20` for the
blind functional judge/validation path. The official public list price checked on 2026-08-31 is
CNY 0.2 input / CNY 2 output per million tokens for Flash requests up to 128K input, and CNY 12
input / CNY 36 output per million tokens for Max requests. Sources:
[Qwen3.5-Flash model information](https://help.aliyun.com/en/model-studio/qwen3-5-flash) and
[Alibaba Cloud Model Studio pricing](https://help.aliyun.com/zh/model-studio/model-pricing).
Promotions are deliberately excluded.

Historical factorial records contain no provider token-usage ledger, so their byte lengths cannot
be converted into an exact bill. The observed maximum serialized generation request/response
payloads were 1,169/1,983 UTF-8 bytes and the observed maximum functional-judge request/response
payloads were 4,602/552 bytes, excluding their static system prompts. These figures are useful for
choosing a candidate token-cap grid only. A formal monetary ceiling still requires exact frozen
input/output token caps, task-specific maximum request sizes, current price references, and the
author's total-cost cap.

## Inputs required for a numeric freeze

The following must be provided together; freezing any one in isolation can invalidate power or cost:

1. approved Atomic and Pair RQ1 variant lists;
2. `K_A` and `K_I`;
3. exact model strata under the frozen model-bound dispatch rule;
4. task-unit counts per candidate or an auditable upper bound;
5. global realization counts, outcome-blind one-realization-per-task allocation, and minimum task
   support per realization;
6. Atomic and Pair total block slots;
7. policy deduplication rule and worst-case `B_A`, `B_I`;
8. provider-specific price/rate limits and retry ceilings;
9. practical margins, multiplicity-family sizes, and power evidence; and
10. one smallest representative smoke request proving actual calls equal the preflight count.

Until all ten are frozen in `rq1_budget_qualification.json`, the honest answer to “what will RQ1
cost?” is a formula and a blocker list—not an invented number.
