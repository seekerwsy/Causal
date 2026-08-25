# Fresh two-family four-arm study freeze

## Status and timing

This is a prospective shortfall amendment and final population/configuration freeze created before any code
generation, Security Oracle output, Functional Oracle output, arm outcome, or effect estimate for
this study. All 60 selected tasks have passed the context-conditioned MechanismSpec binding. Only
the predeclared five-task pilot is now authorized; scaling remains unauthorized until its
protocol-integrity gate passes.

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

## Frozen design

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

The final sample contains 15 CWE-78, 15 CWE-89, 10 CWE-22, 10 CWE-502, 9 CWE-611, and 1
CWE-918 clusters. It draws from seven source lineages; the largest lineage contributes 15/60,
which exactly meets the frozen 25% cap.
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

The outcome-blind audit excluded 52 candidate task units. The deterministic reserve rule then
produced the final 60-task sample; all 60 have exactly one compatible MechanismSpec, with zero
`not_applicable` and zero `unresolved` decisions. These replacements used only prompts and frozen
functional contracts, never arms, generated code, Oracle outputs, or outcomes.

## Pilot and scale rule

The intervention pilot contains five context-qualified tasks spanning both families and five
distinct realizations: executable allowlisting, dynamic SQL identifiers, safe archive extraction,
YAML deserialization, and XML external-entity control. The pilot checks suffix semantics, request closure, code-generation transport,
AST/compile measurement, both Oracles, and total assignment accounting. Scaling may depend only on
protocol integrity: complete artifacts, valid requests, functioning measurement, and no
infrastructure error. Security direction, functionality rate, arm contrast, and significance are
not scale criteria.

## Frozen identities

- study-design bundle SHA-256:
  `f76b21429d9f59d382a253216fc8b5da0fa0d49d9a5bd9e27b0845ec843222a8`;
- pre-binding source tasks SHA-256:
  `59592e535781114e8fc1169ad6a04650f680c2b3623578bbf26a9bcfd4422764`;
- final context-qualified tasks SHA-256:
  `a2f6e481138dbe7f149d0b9ed368bf85e1805ce8531851aea5397209dd300551`;
- context-binding report bundle SHA-256:
  `3001cbac69623a6db6097b293cad9ed3bf5f9558a54219525e493883118e0ffb`;
- formal configuration SHA-256:
  `ec382a700996a93c5551dfaf3c5c31937fe706b90f3c12acb3eef0698b372517`;
- MechanismSpec registry SHA-256:
  `2f70e348d1947891efc6debb81495c66cb255095714bd73d442e442dcb47a85e`;
- intervention executor config SHA-256:
  `4f2acf6327b1450684787bd8b1e96440b22b06b1544954fe7a6372c99a8dadd0`;
- intervention validator config SHA-256:
  `54763ce30f2db7739ba59135a5d8f1e6a8c769781d051c60958fc857011a670c`.

The zero-provider-call preflight closed 60 tasks and 240 assignments with no identity or schema
drift. Its local bundle SHA-256 is
`87dc87720b95840b49f7bb90555edb3560457e4f7c3d103a2746e17347a70a25`.

This amendment supports only the two declared families and one generator model. It cannot be cited
as evidence for the omitted cryptography or identity families, cross-language replication, backend
replication, or a model-general effect.

Execution results, the deterministic seed-range repair, and final evidence limitations are recorded
separately in `2026-08-25-fresh-two-family-four-arm-results.md`; that document supersedes any
pre-repair execution output, but does not alter this prospective population or estimand freeze.
