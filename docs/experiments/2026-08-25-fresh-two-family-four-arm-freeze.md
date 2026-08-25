# Fresh two-family four-arm study freeze

## Status and timing

This is a prospective shortfall amendment and candidate-population freeze created before any code
generation, Security Oracle output, Functional Oracle output, arm outcome, or effect estimate for
this study. Confirmatory generation remains unauthorized until every selected task passes the new
context-conditioned MechanismSpec binding and the predeclared intervention pilot passes.

## Why the former 60-task design cannot be reused

All 60 task units in `four-arm-study-60-python-tasks-v1.jsonl` have been exposed by the previous
four-arm study. The 12 tasks used in the 2026-08-25 intervention engineering validation are a subset
of those 60. Reusing any of them would violate the development/confirmation separation, so the new
selector excludes all 60 task units by identity. The new candidate sample has zero task-unit overlap.

After that exclusion, the original four-family allocation is infeasible without weakening frozen
quality gates:

- identity/authorization/permissions has only 7 fresh task units, below its quota of 15;
- all 46 fresh cryptography/randomness/integrity units come from one lineage, so the family fails
  the minimum-three-lineage requirement and cannot fit under the 15/60 lineage cap.

Neither family is silently reused, pooled, or generalized from another family. They remain explicit
paper-scope shortfalls for later data acquisition or replication.

## Frozen candidate design

- Population: Python tasks in `injection_and_interpreter` and
  `file_parser_external_resource` only.
- Allocation: 30 independent task units per family, 60 total.
- Arms: `absent`, `specific`, `generic`, and `placebo` for every admitted task.
- Assignment count: 240 for one generator model.
- Primary outcome: Oracle-evaluable secure-code yield.
- Primary contrast: paired, cluster-weighted `specific - placebo` assigned-arm ITT.
- Secondary outcomes: code validity, Oracle evaluability, functionality, and joint
  secure-and-functional success.
- Generator: `qwen3.5-flash-2026-02-23`, temperature 0, one frozen request per assignment.
- Intervention executor: `qwen3.5-flash-2026-02-23`.
- Blind intervention and functionality reviewer: `qwen3.7-max-2026-05-20`, non-thinking mode.
- Selection seed: `2026082501`.

The candidate sample contains 15 CWE-78, 15 CWE-89, 10 CWE-22, 10 CWE-502, 9 CWE-611, and 1
CWE-918 clusters. It draws from seven source lineages; the largest lineage contributes 11/60.
Under the frozen planning assumptions (20-point minimum effect, discordant-pair probability 0.30,
two-sided alpha 0.05), the paired-design power is 0.80743. Family-specific effects remain
descriptive heterogeneity estimates.

## Context-binding and reserve rule

The old broad mechanism eligibility does not by itself authorize a task under MechanismSpec v3.
Before any code generation, every candidate must receive an outcome-blind binding based only on its
source prompt and frozen functional contract. A task is admitted only when exactly one realization's
required context holds and its excluded context does not.

If a candidate is `not_applicable` or `unresolved`, it may be replaced only before generation by the
next deterministic candidate under the same seed, family quota, co-selection constraints, and
lineage cap. Every exclusion and reserve admission remains in the ledger. Once 60 context-qualified
tasks are frozen and the first code-generation request is made, no task or quota may be replaced.

## Pilot and scale rule

The intervention pilot contains five context-qualified tasks spanning both families and the active
realization types. The pilot checks suffix semantics, request closure, code-generation transport,
AST/compile measurement, both Oracles, and total assignment accounting. Scaling may depend only on
protocol integrity: complete artifacts, valid requests, functioning measurement, and no
infrastructure error. Security direction, functionality rate, arm contrast, and significance are
not scale criteria.

## Frozen identities

- study-design bundle SHA-256:
  `66e80d9ddbad7832eb68c0a8b39e60b1dab45142bad7a66fe5f9683819725284`;
- materialized candidate tasks SHA-256:
  `9cdacabbf75af4b02de044b879238c7ad2f4a80a38d2af9ea8111db8b853ef68`;
- MechanismSpec registry SHA-256:
  `2f70e348d1947891efc6debb81495c66cb255095714bd73d442e442dcb47a85e`;
- intervention executor config SHA-256:
  `4f2acf6327b1450684787bd8b1e96440b22b06b1544954fe7a6372c99a8dadd0`;
- intervention validator config SHA-256:
  `54763ce30f2db7739ba59135a5d8f1e6a8c769781d051c60958fc857011a670c`.

This amendment supports only the two declared families and one generator model. It cannot be cited
as evidence for the omitted cryptography or identity families, cross-language replication, backend
replication, or a model-general effect.
