# Paired Confirmation and Causal Effects Design

**Date:** 2026-07-12  
**Scope:** M4 — exact paired confirmation, conservative ITT, per-protocol effects, and clustered uncertainty

## 1. Objective

M4 turns confirmed-split interventions and independent Oracle outcomes into exact paired records and
auditable hypothesis-level effects. It replaces permissive dictionary joins and ambiguous missing
outcome handling with a fail-closed coordinate contract.

The primary statistical design is the user-approved conservative option:

- every assigned intervention contributes to the intention-to-treat denominator;
- a protocol failure or non-evaluable Oracle outcome receives zero benefit in the primary ITT point
  estimate;
- per-protocol estimates use only semantically valid, target-changing, side-effect-free, functional,
  evaluable pairs;
- explicit best/worst outcome bounds show how non-evaluable pairs could change the result;
- bootstrap resampling occurs by original `prompt_id`, never by individual model/seed rows.

Oracle records remain the only source of security outcome `Y`. M4 does not infer security from
Prompt TSG, generated code structure, intervention success, or failure reasons.

## 2. Non-Negotiable Boundaries

1. `secure` maps to `Y=0`; `insecure` maps to `Y=1`; `unknown` has no numeric value.
2. Prompt TSG and intervention validation are pre-outcome mechanisms. They may determine protocol
   eligibility but never create or replace `Y`.
3. A malformed, duplicated, missing, extra, stale, or cross-condition committed artifact is a
   contract failure and aborts confirmation. It is not silently dropped or converted to an
   experimental failure.
4. A valid persisted failure state, such as a failed intervention, non-functional generation, or
   `OracleRecord.security_label == unknown`, remains an assigned experimental unit. It contributes
   zero benefit to the conservative ITT estimate and contributes its mathematically valid range to
   sensitivity bounds.
5. Discovery and confirmation samples remain disjoint. Selected hypotheses originate from the
   discovery split; M4 effects use only prompts marked `split="confirm"`.
6. No flat Prompt TSG feature or shadow projection participates in pairing or estimation.

## 3. Assignment and Pairing Coordinates

### 3.1 Assignment unit

One assigned unit is identified by:

```text
(prompt_id, hypothesis_id, intervention_id, model_id, seed_id)
```

`intervention_id` binds the concrete counterfactual prompt and must map to exactly one
`InterventionRecord`. A deterministic `pair_id` is `pair_` plus the lowercase SHA-256 of the
canonical assignment coordinates and the bound observed/counterfactual request and code IDs. Raw
prompt text is not included in the identifier or output records.

The assignment universe is the finite Cartesian product of every selected, persisted intervention
attempt and the configured generation `(model_id, seed_id)` axes. It is bounded by the existing
generation request limit. Assignment construction rejects duplicate models, duplicate seeds,
duplicate intervention IDs, duplicate intervention coordinates, or an oversized product.

### 3.2 Exact producer binding

For every assignment, M4 requires exactly one observed Oracle coordinate for
`(prompt_id, model_id, seed_id)`. A successful counterfactual generation requires exactly one
counterfactual Oracle coordinate additionally bound to `intervention_id` and `hypothesis_id`.

The following are structural contract errors:

- duplicate or extra Oracle records;
- missing observed Oracle records;
- missing counterfactual Oracle records for a successfully generated counterfactual;
- condition, request, code, prompt, hypothesis, intervention, model, or seed mismatch;
- an Oracle record whose request/code provenance does not match the committed generated-code
  producer;
- an intervention referencing an unselected hypothesis or a non-confirm prompt;
- stale producer inputs or catalog/policy fingerprints.

Structural errors raise a sanitized `ANALYSIS_INVALID`/manifest error before publication. Pairing
never uses dictionary overwrites, `continue`-on-mismatch behavior, or best-effort joins.

### 3.3 Recorded protocol failures

An intervention attempt with an explicit finite `FailureReason` still creates one `PairResult` per
configured model/seed assignment. If no counterfactual should be generated because the patch was
invalid, the absence is expected and recorded rather than treated as artifact corruption.

For successful interventions, generation and Oracle stages must encode parse, functional, or
security non-evaluability in their committed records. An absent record is not an acceptable encoding
of failure.

## 4. Pair Result Schema 2.0

`PairResult` becomes a frozen, strict, bounded schema with `extra="forbid"` and a breaking result
schema version `2.0`. It contains:

- assignment coordinates and deterministic `pair_id`;
- observed/counterfactual request IDs, code IDs, and code SHA-256 values when present;
- typed `FactorType`, expected direction, and finite `FailureReason`/flip enums;
- intervention validity facts (`patch_success`, `round_trip_valid`, `semantic_valid`,
  `target_changed`, `side_effect`);
- Oracle parse/functional states and typed security labels;
- `outcome_observed` and `outcome_counterfactual` as `0`, `1`, or `None`;
- `per_protocol_delta` as `-1`, `0`, `1`, or `None`;
- `itt_delta` as exactly `-1`, `0`, or `1`;
- `sensitivity_delta_low` and `sensitivity_delta_high` in `{-1, 0, 1}`;
- `eligible_per_protocol` and a deterministic primary failure reason.

The model validator recomputes all derived fields. Callers cannot supply inconsistent deltas,
eligibility, flip types, or failure priorities.

Failure priority is finite and deterministic:

1. intervention failure already recorded by M3;
2. observed/counterfactual parse failure;
3. observed/counterfactual functional failure;
4. Oracle unknown;
5. no failure.

No error, repr, traceback local, or schema detail contains raw prompt/code text.

## 5. Estimands

Let `Y(0)` be the observed-prompt Oracle risk outcome and `Y(1)` the counterfactual-prompt Oracle
risk outcome. Lower is safer.

### 5.1 Per-protocol risk difference

A pair is PP-eligible only when:

- the patch, round trip, and semantic checks succeeded;
- the intended target changed;
- no non-target side effect occurred;
- both generated programs parsed and passed the configured functional check;
- both Oracle outcomes are `secure` or `insecure`.

For eligible pair `i`:

```text
delta_pp_i = Y_i(1) - Y_i(0)
RD_PP = mean(delta_pp_i over PP-eligible pairs)
```

Ineligible pairs have `per_protocol_delta=None` and never enter the PP denominator.

### 5.2 Conservative intention-to-treat risk difference

Every assigned pair enters ITT. If both numeric outcomes exist, `itt_delta` is their difference. If
the intervention or either outcome is non-evaluable, `itt_delta=0`. This is a conservative
no-benefit imputation for a risk-reducing intervention; it does not assert that the missing security
outcome was secure.

```text
RD_ITT = mean(itt_delta_i over every assigned pair)
```

### 5.3 Sensitivity bounds

Each pair also carries the sharp range compatible with the observed information:

| Observed `Y(0)` | Counterfactual `Y(1)` | Delta range |
|---|---|---|
| known | known | exact `Y(1)-Y(0)` |
| `0` | unknown | `[0, 1]` |
| `1` | unknown | `[-1, 0]` |
| unknown | `0` | `[-1, 0]` |
| unknown | `1` | `[0, 1]` |
| unknown | unknown | `[-1, 1]` |

Hypothesis-level sensitivity bounds are the means of pairwise lower and upper bounds across the ITT
assignment universe. They are reported alongside, not substituted for, PP or ITT estimates.

### 5.4 Flip and protocol rates

Secure-flip rate uses evaluable pairs observed as insecure. Insecure-flip rate uses evaluable pairs
observed as secure. Their numerators and denominators are persisted separately; an empty denominator
produces `None`, not `0.0`.

Side-effect rate is calculated over unique intervention attempts, not duplicated model/seed rows.
Protocol completion and Oracle-evaluable rates are reported over assigned pairs.

## 6. Cluster Bootstrap and Multiplicity

Here, a cluster is a design-based resampling unit, not a machine-learning cluster discovered by an
algorithm such as k-means. Within one hypothesis, every pair that shares the same original
`prompt_id` belongs to one cluster. Model and seed rows from that prompt are therefore sampled as a
single block. Hypotheses are estimated separately, so a cluster never combines rows from different
hypotheses.

For example, three prompts with two models and two seeds produce twelve pair rows but only three
independent prompt clusters. A bootstrap draw of `[p2, p2, p1]` includes all four rows belonging to
`p2` twice, all four rows belonging to `p1` once, and no rows from `p3`. Row-wise resampling is
forbidden because it would treat repeated model/seed measurements as independent and make confidence
intervals artificially narrow.

Bootstrap resampling is deterministic and clustered by `prompt_id` within each hypothesis:

1. sort unique prompt IDs;
2. sample the same number of prompt clusters with replacement;
3. include every model/seed pair belonging to each sampled cluster;
4. compute PP and ITT estimates independently for that replicate;
5. repeat exactly `bootstrap_samples` times with a hypothesis-specific seed derived from the global
   run seed and canonical hypothesis ID.

ITT always has a replicate value. A PP replicate with no eligible pair is invalid rather than
imputed. M4 records the valid PP replicate count and requires a configured minimum valid fraction;
it performs no unbounded retries. Percentile interpolation is implemented explicitly so Python,
NumPy, and Pydantic version changes cannot alter endpoints.

Confirmation evaluates a family of selected hypotheses. It uses a Bonferroni-adjusted confidence
level `1 - (1-ci_level)/H`, where `H` is the number of hypotheses with assigned confirmation units.
Both unadjusted point estimates and adjusted confidence intervals are persisted.

## 7. Effect Result and Status

`EffectRecord` becomes frozen and strict with result schema version `2.0`. It stores:

- hypothesis/factor/scope coordinates;
- attempted, PP-eligible, Oracle-evaluable, and unique prompt counts;
- PP and ITT risk differences with adjusted cluster-bootstrap intervals;
- valid bootstrap replicate counts;
- sensitivity lower/upper risk differences;
- secure/insecure flip numerators, denominators, and nullable rates;
- unique-intervention side-effect rate;
- protocol completion and Oracle-evaluable rates;
- finite status and failure reason enums;
- estimator, schema, bootstrap, confidence-adjustment, and random-seed provenance.

A hypothesis is `confirmed` only when all are true:

- attempted, PP-eligible, unique-prompt, and valid-bootstrap denominators meet configured minima;
- `RD_PP < 0` and adjusted PP CI upper bound `< 0`;
- `RD_ITT < 0` and adjusted ITT CI upper bound `< 0`;
- the worst-case sensitivity upper bound is `<= 0`;
- secure-flip rate meets its configured minimum;
- insecure-flip rate is not above its configured maximum;
- side-effect rate is not above its configured maximum.

`directional` means both PP and ITT point estimates are risk-reducing but at least one confirmation
gate is unmet. `unsupported` covers insufficient denominators, no effect, opposite direction,
excess harm flips, excess side effects, or invalid bootstrap support. Failure-reason precedence is
finite and tested. A confirmed result never carries a failure reason.

## 8. Confirmation Stage Transaction

`confirm` holds committed producer leases in canonical stage-name order for:

- `discover` selected hypotheses;
- `intervene` intervention attempts;
- `run-oracle-observed`;
- `run-oracle-counterfactual`.

Input-aware holds are used wherever the producer contract exposes inputs. The leases span strict
readback, coordinate validation, pair construction, estimation, output sealing, manifest commit, and
rollback. Concurrent force-runs receive a manifest conflict; they never observe or overwrite a
partial transaction.

The stage also binds the current prompt input so it can prove interventions use only confirm-split
prompts and selected hypotheses came from the committed discovery output. Pair and effect JSONL
outputs use the existing preserve-committed transaction. Any error restores the previous output and
manifest byte-for-byte.

## 9. Configuration

`AnalysisConfig` is strict and bounded. It retains existing thresholds and adds only parameters
required by this design:

- minimum unique prompts;
- minimum valid PP bootstrap fraction;
- maximum insecure-flip rate for confirmation.

`bootstrap_samples`, confidence level, denominator thresholds, rates, and the assignment product are
validated before execution. Zero, negative, non-finite, boolean-as-integer, and excessive values are
rejected. There is no open-ended estimator or rule registry.

## 10. Failure Semantics

- Schema, coordinate, provenance, split, duplicate, and artifact-coverage failures abort with a
  sanitized stable error and publish nothing.
- Expected protocol failures remain typed data and influence ITT/bounds.
- Unknown Oracle outcomes are never converted into secure/insecure labels.
- Empty assignment universes and missing selected hypotheses fail closed; they do not produce a
  vacuous confirmed effect.
- Bootstrap insufficiency yields a typed unsupported effect only when the underlying pair artifact
  is valid. Invalid pair input aborts estimation.
- All traversals, products, grouping maps, and bootstrap loops have explicit finite bounds.

## 11. Testing and Acceptance

M4 is complete only when tests prove:

1. duplicate, missing, extra, stale, and cross-condition coordinates fail before publication;
2. pair construction is invariant to input order and never silently skips or overwrites;
3. pair IDs and outputs are deterministic across Python hash seeds;
4. every secure/insecure/unknown outcome combination produces the specified PP, ITT, bound, and
   flip values;
5. protocol failure priority is exact and does not leak prompt/code text;
6. clustered bootstrap keeps model/seed rows together, is deterministic, order-invariant, bounded,
   and differs from an invalid row-wise bootstrap on adversarial data;
7. PP-empty replicates and insufficient valid replicate fractions are handled exactly as specified;
8. multiplicity-adjusted intervals and every confirmation gate are mutation-sensitive;
9. flip denominators are nullable rather than reported as false zero rates;
10. discover/confirm sample separation is enforced;
11. confirm holds all producer leases throughout computation and rollback;
12. forced failures, interrupts, seal tampering, and concurrent force runs preserve the prior commit;
13. PairResult/EffectRecord v1 or permissive artifacts cannot pass v2 readback or skip validation;
14. Python 3.10, Python 3.12, minimum Pydantic, Ruff, compile, static, and real-Oracle regressions
    pass;
15. run-all final pair labels remain exactly traceable to committed Oracle records.

## 12. Non-Goals

- M4 does not estimate mediation, controlled direct effects, or natural indirect effects.
- M4 does not claim population generalization beyond the configured confirmation sample.
- M4 does not replace the Semgrep+Bandit Oracle or infer outcomes from Prompt TSG.
- M4 does not add adaptive stopping, Bayesian priors, model weighting, or an estimator plugin system.
- M4 does not hide protocol failures by dropping them from the ITT assignment universe.

## 13. Consequences

The design is intentionally stricter than the current implementation. Old pair/effect artifacts must
be regenerated. Exact pairing and conservative ITT reduce optimistic bias, while PP and sensitivity
bounds preserve interpretability. Clustered, multiplicity-adjusted uncertainty is more conservative
than row-wise bootstrap but matches the experimental dependence structure and independent-split
claim.
