# Factorial SQL scaffold-repair follow-up v1 results

**Evidence type:** newly run prospective follow-up

**Study:** `factorial-sql-scaffold-repair-qwen35-v1`

**Execution commit:** `efdb6dc`

**Execution date:** 2026-08-27

**Result bundle:** `data/formal/results/factorial-sql-scaffold-repair-qwen35-v1`

**Deployment archive SHA-256:**
`2c30adc59b4871219dde06bbc18ea12be51126fc7fa45b490627f683b9adc55a`
**Downloaded result archive SHA-256:**
`219629c2a66f3b11841498484d550fba35fd0843294b49ed9e7772b29721899d`

## Evidence boundary

This is a separately frozen follow-up to the completed from-scratch v3 confirmation.
The v3 aggregate ceiling motivated the scaffold context, but all 30 predecessor task
units were retained. Every follow-up prompt and task has a new identity, and no
task-specific predecessor outcome was used for inclusion, exclusion, or weighting.

The result estimates a context-conditioned prompt repair-policy effect on deterministic
Python DB-API starter implementations. It is not a representative estimate for natural
vulnerability-repair prompts, all CWE-89 tasks, or programming tasks. Because the full
security endpoint requires both controls, a positive interaction is a joint prompt-policy
interaction under this endpoint; it is not a universal mechanism-synergy claim.

## Frozen design and input qualification

- 30 predecessor task units retained exactly;
- 30 new task and prompt identities;
- one generation model: `qwen3.5-flash-2026-02-23`;
- two equally weighted intervention orders;
- four complete-block cells per task unit and order;
- 240 assignments;
- static profile `python.cwe89.dynamic_identifier_and_values.v2`;
- blinded Qwen3.7-Max Functional Judge after Python AST/compile validation;
- assigned-cell, equally weighted task-unit ITT;
- two-sided secure-yield interaction as the primary estimand;
- 5,000-draw max-|T| task-unit bootstrap at familywise alpha 0.05;
- practical interaction margin 0.20, maximum unknown fraction 0.10, and
  A11-versus-A00 functionality non-inferiority margin 0.10.

The corpus digest is
`bade1da48befac94873ea46465d98befc36a29ce3d012266c7ba098cd75e893f`.
Before provider calls, every deterministic starter was valid Python, Oracle-evaluable,
and `unsafe` for both value parameterization and identifier control. The prompt did not
label the starter as insecure or vulnerable.

## Development-only scale-up gate

A disjoint four-task canary closed 32/32 assignments. All code was syntactically valid
and Oracle-evaluable. The value-only target produced 100% value parameterization while
leaving identifier control at 0%; the identifier-only target produced 100% identifier
control with 25% spontaneous value parameterization; A11 produced both controls and
100% secure yield. A11 functionality was 100%. The canary authorized scale-up but is not
included in the formal 30-task-unit estimates or any scientific significance claim.

## Execution and verification

The formal run executed on Linux with Python 3.12.13 on an NVIDIA A800 host. Provider
credentials were inherited in process and were not written to the artifact.
`PYTHONDONTWRITEBYTECODE=1` was set, and deployment/result roots were checked for generated
bytecode. Runtime was 1,266.41 seconds; peak reported resident memory was 41,676 KiB.

All 240 assignments reached terminal measurement records. The generic bundle verifier
passed remotely and again after download. The estimator-independent verifier reported:

```json
{"assignments":240,"coordinates":5,"primary_intervals":1,"secondary_intervals":3,"status":"FACTORIAL_INFERENCE_VERIFIED"}
```

The independently implemented mechanism-trace verifier also passed for both predeclared
diagnostic endpoints and all 240 assignments.

After archival, the reviewer-invokable stored-result verifier independently rederived
all assignment bindings, outcomes, five task-unit-weighted result coordinates, the
primary max-|T| interval, three secondary intervals, and both mechanism-trace endpoints:

```text
prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-scaffold-repair-qwen35-v1
```

It returned `FACTORIAL_RESULT_BUNDLE_VERIFIED` for 240 assignments and 30 task units.
The same verifier also reproduced the predecessor v3 bundle, including its zero
interaction, from the stored measurement ledger.

## Primary and secondary outcomes

| Cell | Assigned policy | Secure yield | Code valid | Oracle evaluable | Functionality |
| --- | --- | ---: | ---: | ---: | ---: |
| A00 | preserve both starter behaviors | 0/60 (0.0%) | 60/60 | 60/60 | 60/60 (100.0%) |
| A10 | value binding only | 7/60 (11.7%) | 60/60 | 60/60 | 54/60 (90.0%) |
| A01 | identifier control only | 10/60 (16.7%) | 60/60 | 60/60 | 60/60 (100.0%) |
| A11 | both requirements | 59/60 (98.3%) | 60/60 | 60/60 | 59/60 (98.3%) |

The secure-yield estimates were:

- factor 1, A10-A00: `+0.1167`;
- factor 2, A01-A00: `+0.1667`;
- joint, A11-A00: `+0.9833`;
- primary interaction: `+0.7000`;
- simultaneous interaction interval: `[+0.5667, +0.8333]`.

The primary interaction interval excludes zero and the point estimate exceeds the frozen
0.20 practical margin. Oracle evaluability was 100%, so observed and unknown-bound
estimates coincide. A11-A00 functionality was `-0.0167`, passing the frozen `-0.10`
non-inferiority gate. The complete predeclared primary claim gate therefore passed.

The max-|T| secondary intervals were:

- factor 1: `[-0.0015, +0.2349]`, does not exclude zero;
- factor 2: `[+0.0167, +0.3167]`, excludes zero;
- joint: `[+0.9447, +1.0000]`, excludes zero.

These factor effects use the conjunctive full-security endpoint. They should not be read
as direct estimates of each mechanism's implementation fidelity.

## Mechanism-trace diagnostics

| Endpoint | A00 | A10 | A01 | A11 |
| --- | ---: | ---: | ---: | ---: |
| value parameterization safe | 1/60 (1.7%) | 60/60 (100.0%) | 10/60 (16.7%) | 60/60 (100.0%) |
| identifier control safe | 0/60 (0.0%) | 7/60 (11.7%) | 60/60 (100.0%) | 59/60 (98.3%) |

The intended factor-specific response is visible despite treatment crossover: A10 changes
value handling strongly without reliably changing identifier control, while A01 changes
identifier control strongly and sometimes also induces value parameterization. These are
post-assignment diagnostics, not mediators or denominator filters.

## Case and realization audit

Both frozen orders produced a large interaction:

- factor 1 then factor 2: approximately `+0.667`;
- factor 2 then factor 1: approximately `+0.733`.

The intervention executor emitted byte-identical four-cell bundles across orders for 28
of 30 tasks. The other two differed only in punctuation/conjunction style. Thus the run
does not establish substantive order sensitivity or realization robustness; the two
coordinates mostly act as separately seeded repetitions of the same policy text and are
retained exactly as frozen.

The single A11 failure was `rank_projects` in one order. The model validated the identifier
but then attempted to bind the identifier through a `?` value placeholder; the Security
Oracle marked identifier control unsafe and the Functional Judge rejected the resulting
query semantics. Six A10 functionality failures had the same overgeneralization pattern,
especially in aggregate and grouping tasks: the model tried to parameterize identifiers
when instructed only to bind values. This is a real isolated-policy tradeoff, not an
infrastructure failure.

The 7 secure A10 assignments and 10 secure A01 assignments are treatment crossover. The
model sometimes added the other control despite the matched no-op. Assigned-cell ITT
correctly retains these cases; removing them would inflate the interaction.

## Cross-context interpretation

For the same 30 task units and model, the from-scratch v3 study had A00=96.7%, A11=98.3%,
and interaction=0.0. The scaffold-repair follow-up had A00=0.0%, A11=98.3%, and
interaction=+70.0 percentage points. This descriptive contrast is strong evidence that
source-generation context governs observable prompt-policy responsiveness.

The context itself was not randomized between studies, and the follow-up was motivated
by the v3 aggregate result. Therefore the difference is exploratory context heterogeneity,
not a randomized causal effect of “scaffold versus from scratch.” The defensible result is:

> On this controlled repair corpus, jointly assigning value-binding and finite-domain
> identifier-control requirements produced a large, statistically detectable increase in
> Oracle-evaluable secure-code yield while satisfying the frozen functionality
> non-inferiority gate.
