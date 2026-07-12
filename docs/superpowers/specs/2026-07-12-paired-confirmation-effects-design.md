# Unified Feature Graph, Paired Confirmation, and Causal Effects Design

**Date:** 2026-07-12
**Revised:** 2026-07-13
**Scope:** M4 — unified feature graph, typed reversible interventions, exact paired confirmation, and clustered effects

## 1. Objective

M4 extends the authoritative Prompt TSG into one typed feature view for task-function,
safety-control, and presentation/placebo features. All three families share canonical graph deltas,
typed add/remove operations, provenance, and round-trip validation. They remain separate experiment
families with separate invariants and outcomes; a unified graph never implies a pooled effect.

M4 also turns confirmed-split safety interventions and independent Oracle outcomes into exact paired
records and auditable hypothesis-level effects. It replaces permissive dictionary joins and
ambiguous missing outcome handling with a fail-closed coordinate contract. Safety confirmation is
the first complete outcome-estimation family built on the unified feature graph.

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
7. Task-function, safety-control, and presentation-control features share one graph record and one
   delta engine, but their observations are never pooled into one denominator or status.
8. A functional change is not relabeled as a safety side effect, and a presentation change is not
   relabeled as a task or safety mechanism. Cross-family changes are explicit graph deltas.

### 2.1 Safety-neutral prompt contrast

The untreated prompt is a neutral functional specification. It may name the required domain objects
and operations—such as a user-provided filename, a database lookup, or invoking a fixed tool—but it
must not ask the model to introduce a vulnerability, suppress a protection, use a known unsafe
construction, evade an analyzer, or produce an insecure outcome. CWE and outcome labels remain
metadata and are not inserted into prompt text.

The treated prompt is not neutral with respect to the treatment: it adds one positive safety
requirement. It must nevertheless remain neutral with respect to the desired measured outcome. It
does not claim that the baseline is vulnerable, predict that the new code will be secure, show an
exploit, or provide an unsafe implementation as a contrast. Treatment clauses use positive
instructions such as “bind user-controlled values through database parameters” rather than naming
and negating a vulnerable construction.

Prompt roles are explicit and finite: `neutral_baseline`, `positive_safety_control`,
`task_function_variant`, and `presentation_control`. Safety addition is allowed only from an attested
`neutral_baseline`; safety removal is allowed only from a `positive_safety_control` that is bound to
its exact neutral counterpart. Task and presentation experiments use their corresponding roles. A
strict, committed neutrality manifest binds each prompt role and counterpart relation to the exact
prompt SHA-256 and reviewed prompt-catalog version. A missing, stale, duplicated, or mismatched
attestation aborts the stage. The manifest is reviewed pre-outcome and cannot contain generated code,
Oracle labels, or post-treatment evidence.

This is a reviewed data contract, not an extensible keyword classifier or an LLM safety judge. The
finite treatment templates and their positive polarity are part of the versioned intervention
catalog digest; changing one invalidates downstream skip state and requires review.

### 2.2 Graph-driven, text-executed intervention

The intervention is deliberately hybrid:

1. the selected hypothesis and authoritative Prompt TSG choose one exact target feature and
   `add`/`remove` operation;
2. the finite intervention catalog constructs a bounded executor request for that typed operation;
3. the run-locked executor modifies the prompt text, because prompt text is what the code-generation
   model actually receives;
4. the modified text is independently re-extracted into Prompt TSG 2.1;
5. graph comparison must prove the exact family-specific target delta and reject every disallowed
   cross-family change.

M4 supports finite execution modes and executors:

```text
InterventionMode = TEXT_NATIVE | GRAPH_NATIVE
InterventionExecutor = DETERMINISTIC | LLM
```

`TEXT_NATIVE` asks the chosen executor to apply the FeatureSpec directly to the original text and
derives the realized graph delta afterward. `GRAPH_NATIVE` first applies the typed patch to an
immutable working copy of the source graph, records the intended graph delta, and asks the executor
to render that delta into text. It then requires intended and realized graph deltas to match exactly.
Neither mode mutates the committed source graph.

The deterministic executor uses finite, reviewed, syntax-aware templates. The LLM executor may
improve fluency, but it is only a text-edit implementation mechanism. It cannot choose the feature,
operation, graph patch, expected direction, eligibility, or outcome. It receives no generated code,
Oracle record, security label, or post-treatment evidence. It has no tools and returns one strict,
bounded prompt candidate.

The authoritative validator—not the LLM—decides whether an intervention succeeded. It independently
re-extracts Prompt TSG, validates neutrality, verifies family invariants, and compares intended and
realized deltas. A candidate with extra requirements, missing target change, presentation drift
outside the allowed projection, or any other mismatch is rejected.

One run locks exactly one mode, executor type, executor model/version, system-template SHA-256,
catalog digest, and decoding configuration in its manifest. The experiment does not introduce an
executor term or interaction into the causal model. Conditional on passing the complete graph and
neutrality contract, the executor is treated as a correct implementation of the selected feature
operation. This is an explicit simplifying assumption; runs using different executor policies are
separate replications and are not automatically pooled.

There is exactly one semantic candidate per assignment. Transport-level retries may resend identical
request bytes under the existing bounded provider policy, but M4 never asks for a new wording after a
candidate fails graph validation and never selects the most favorable candidate. Executor runtime,
authentication, or locked-model failures abort the stage; a well-formed returned candidate that fails
the intervention contract becomes a typed protocol failure and remains in ITT.

Safety removal is the inverse of safety addition, not an unsafe instruction. It may remove only a
catalog-owned positive clause whose span, text SHA-256, feature ID, and originating neutral prompt
are committed. Removal must restore the attested neutral text exactly; it cannot insert wording such
as “skip validation” or “use an unsafe API.” Adding and then removing the same clause must produce
`False -> True -> False` for the target factor and byte-for-byte restore the original prompt.

The same neutral/safety text pair supplies one experimental contrast. Reporting the reverse contrast
as the negative of the forward contrast is allowed for audit, but it is not a second independent
sample and never doubles a denominator. An independently sourced positive-control prompt may enter a
separate removal cohort only when it has its own neutral counterpart and provenance.

### 2.3 Unified feature graph

Prompt TSG 2.1 remains one canonical `MultiDiGraph`. It adds finite enums:

```text
FeatureFamily = TASK_FUNCTION | SAFETY_CONTROL | PRESENTATION_CONTROL
FeatureOperation = ADD | REMOVE
```

Every intervenable semantic identity has one catalog-bound `feature_id` and exactly one family.
Existing task operations, data objects, sources, and sinks form the task-function layer. Safety
requirements, guards, trust boundaries, and security assumptions form the safety-control layer. A
new bounded `PRESENTATION_FEATURE` node type represents reviewed surface controls such as instruction
ordering or list formatting; presentation edges cannot participate in source-to-sink or guard motif
queries.

Feature-family attributes, presentation kinds, and their permitted edge types use strict finite
allowlists. The catalog is immutable, versioned, and included in the Prompt TSG stage-contract
digest. Arbitrary labels, runtime registration, LLM-generated feature definitions, and an open-ended
rule registry are forbidden. Prompt TSG 2.0 records must be regenerated rather than silently
upgraded.

One graph may contain all three typed layers, but consumers use explicit projections:

- task projection: operations, requirements, data, APIs, sources, and sinks;
- safety projection: safety requirements, guards, assumptions, trust boundaries, and motifs;
- presentation projection: reviewed surface-form nodes and ordering/format relations.

No projection is stored as an authoritative flat dictionary. Each is recomputed from the canonical
graph and checked against graph bounds and catalog versions.

### 2.4 Canonical GraphDelta and family invariants

Every intervention produces a frozen `GraphDeltaRecord` containing:

- before/after graph IDs and SHA-256 values;
- feature family, feature ID, operation, intervention mode, executor identity/version,
  system-template SHA-256, operator version, and catalog digest;
- intended graph/delta commitments for graph-native execution and realized commitments for every
  accepted candidate;
- canonical added/removed node semantic identities;
- canonical added/removed edge semantic identities;
- before/after task, safety, and presentation projection commitments;
- target-changed, reversible, and cross-family-change flags;
- a digest over the complete delta.

The same delta engine applies different invariants:

| Experiment family | Allowed target change | Required invariants | Outcome family |
|---|---|---|---|
| safety control | one safety feature `False <-> True` | task projection unchanged; non-target safety features unchanged | Semgrep+Bandit security `Y` |
| task function | one reviewed task feature added/removed | non-target task features and safety projection unchanged | independent functional outcome contract |
| presentation control | one reviewed surface feature added/removed | complete task and safety projections unchanged | placebo security diagnostic or presentation metric |

Any delta outside the selected row is a typed side effect or semantic drift. Safety estimation rejects
it from PP while retaining the assignment in ITT. Task-function and presentation experiments use
their own eligibility and effect records; they are never converted into safety pairs merely because
an Oracle label is available.

M4 implements schema, canonical delta construction, add/remove reversibility, and invariant
validation for all three families. It implements complete paired outcome estimation for the safety
family and a security-outcome negative-control diagnostic for presentation features. A task-function
effect requires a separately committed `FunctionalOutcomeRecord`; without an independent functional
validator the graph delta may be audited but no functional causal claim is published.

## 3. Assignment and Pairing Coordinates

### 3.1 Assignment unit

One safety or presentation assigned unit is identified by:

```text
(prompt_id, hypothesis_id, feature_family, feature_id, operation,
 intervention_id, model_id, seed_id)
```

`intervention_id` binds the concrete counterfactual prompt and must map to exactly one
`InterventionRecord`. A deterministic `pair_id` is `pair_` plus the lowercase SHA-256 of the
canonical assignment coordinates and the bound observed/counterfactual request and code IDs. Raw
prompt text is not included in the identifier or output records.

Forward and reverse views of the same exact text pair share one `contrast_id`. The assignment
validator rejects attempts to publish both views as independent rows for the same model/seed.

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
- typed feature family, feature ID, add/remove operation, expected direction, and `contrast_id`;
- run-locked intervention mode and executor-policy SHA-256 as provenance, not as an estimand;
- a safety `FactorType` only when `feature_family == SAFETY_CONTROL`;
- finite `FailureReason` and flip enums;
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

This section defines the safety-control estimand. Presentation controls reuse exact pairing only as a
negative-control diagnostic and cannot receive `confirmed` safety-mechanism status. Task-function
features require a functional outcome estimand defined by their independent outcome contract.

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
- safety feature family, feature ID, operation, and contrast direction;
- attempted, PP-eligible, Oracle-evaluable, and unique prompt counts;
- PP and ITT risk differences with adjusted cluster-bootstrap intervals;
- valid bootstrap replicate counts;
- sensitivity lower/upper risk differences;
- secure/insecure flip numerators, denominators, and nullable rates;
- unique-intervention side-effect rate;
- protocol completion and Oracle-evaluable rates;
- finite status and failure reason enums;
- estimator, schema, bootstrap, confidence-adjustment, and random-seed provenance;
- intervention mode and executor-policy SHA-256, with exact equality required inside one effect
  group.

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

Presentation-control diagnostics report `consistent_with_null`, `unexpected_security_shift`, or
`unsupported` in a separate strict `ControlEffectRecord`; they never report `confirmed` and are not
included in safety multiplicity counts. A task-function graph delta reports only structural
validation until a committed functional outcome artifact is present, after which a separate
`FunctionalEffectRecord` and estimand are required.

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

The intervention producer also commits `GraphDeltaRecord` outputs. Confirmation requires exact
coverage between intervention attempts and deltas, rejects duplicate forward/reverse publication of
one contrast, and verifies the feature-catalog digest before reading any outcome.

## 9. Configuration

`AnalysisConfig` is strict and bounded. It retains existing thresholds and adds only parameters
required by this design:

- minimum unique prompts;
- minimum valid PP bootstrap fraction;
- maximum insecure-flip rate for confirmation.

Feature families, operations, catalogs, and validators are code-level finite enums/contracts rather
than user-extensible configuration.

`InterventionConfig` selects one run-wide intervention mode and executor. LLM execution additionally
binds provider type, endpoint identity, model ID, system-template SHA-256, decoding parameters,
request/response size limits, timeout, and bounded transport retry policy. Secrets are loaded from
the environment and never persisted. A deterministic executor remains available for offline demo and
reproducibility matrices; there is no silent fallback between executor types.

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
- A feature-family mismatch, disallowed cross-family delta, non-reversible catalog operation, or
  duplicated forward/reverse contrast aborts confirmation.
- A mismatched executor model/configuration, unavailable executor runtime, malformed provider
  protocol, or changed executor manifest binding aborts the intervention stage. A returned candidate
  that fails realized-delta validation is a typed intervention failure and is never semantically
  retried.
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
16. one Prompt TSG round-trip preserves task, safety, and presentation layers and rejects invalid
    cross-layer edges;
17. safety add/remove operations are exact inverses and cannot insert an unsafe instruction;
18. the same forward/reverse text contrast cannot be counted twice;
19. task-function, safety-control, and presentation-control mutations change only their permitted
    graph projections;
20. presentation negative controls cannot receive safety-confirmed status, and task-function deltas
    cannot publish an effect without a committed independent functional outcome.
21. deterministic and LLM executors both pass the same graph/neutrality boundary, while LLM attempts
    to add an extra feature, leak an outcome, follow prompt-injected instructions, or omit the target
    fail closed;
22. an LLM candidate receives no semantic retry or favorable-candidate selection, and executor
    model/template/configuration drift invalidates skip state;
23. text-native realized deltas and graph-native intended/realized deltas are deterministic after
    candidate capture, fully committed, and mutation-sensitive.

## 12. Non-Goals

- M4 does not estimate mediation, controlled direct effects, or natural indirect effects.
- M4 does not claim population generalization beyond the configured confirmation sample.
- M4 does not replace the Semgrep+Bandit Oracle or infer outcomes from Prompt TSG.
- M4 does not add adaptive stopping, Bayesian priors, model weighting, or an estimator plugin system.
- M4 does not hide protocol failures by dropping them from the ITT assignment universe.
- M4 does not treat the reverse view of one text pair as independent evidence.
- M4 does not publish a functional causal effect before an independent, committed functional
  validator exists.
- M4 does not pool feature families into one score, denominator, confidence interval, or status.
- M4 does not estimate an executor main effect or feature-by-executor interaction. Executor policy is
  locked per run and different policies are reported as separate replications.
- M4 does not allow an intervention LLM to judge its own graph delta, eligibility, or security
  outcome, and does not treat an unvalidated LLM response as a successful intervention.

## 13. Consequences

The design is intentionally stricter than the current implementation. Prompt TSG 2.0 and old
pair/effect artifacts must be regenerated. A unified graph and delta engine prevent parallel,
inconsistent representations while typed experiment families prevent invalid statistical pooling.
Exact pairing and conservative ITT reduce optimistic bias, while PP and sensitivity bounds preserve
interpretability. Clustered, multiplicity-adjusted uncertainty is more conservative than row-wise
bootstrap but matches the experimental dependence structure and independent-split claim.
