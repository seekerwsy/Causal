# Method/data integration readiness, 2026-09-01

## Status

```text
METHOD_DATA_INTEGRATED_READY
```

This is implementation and data-identity evidence only. It is not a formal
protocol activation, qualification acceptance, Discovery run, Confirmation
run, or scientific result.

## Frozen coordinates

- completed data foundation commit: `71baa862c98f`
- integrated method commit: `2ff096d`
- archived-data/source-population commit under test: `41301f61d0cb`
- canonical reviewer data:
  `data/dataset-curation/reviewer-task-unit-dataset-v5`
- data manifest SHA-256:
  `33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`
- source-population rule: `QUALITY_INCLUDED` and language `python`
- source-population task units: `381`
- sorted task-unit ID-set SHA-256:
  `d172831733911a29bfe4755adec05b86490d7e72873d5f03bca30d0ad5a819e8`
- technical-readiness diagnostic subset: `101`, not an admission rule
- environment: Windows, Python `3.12.13`, repository virtual environment

No prospective formal role, Prompt TSG, arm, generated program, Oracle
outcome, provider result, or effect claim entered these coordinates.

## Reproduction

From repository root with `PYTHONPATH` bound to `src`:

```text
.venv\Scripts\python.exe -m pytest -m reviewer -q
.venv\Scripts\python.exe -m pytest -o addopts='' -q
.venv\Scripts\python.exe -m prompt_mechanism_study.cli curate finalize-contract-content verify data\dataset-curation\reviewer-task-unit-dataset-v5
.venv\Scripts\python.exe -m prompt_mechanism_study.cli study smoke .test-tmp\method-data-integrated-ready-smoke-20260901-01
.venv\Scripts\python.exe -m prompt_mechanism_study.cli study verify-result .test-tmp\method-data-integrated-ready-smoke-20260901-01
```

Observed results:

- reviewer suite: `63 passed`
- complete retained suite: `157 passed`
- data verifier: `VERIFIED_DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED`
- schema-3 smoke: 19-file package, 80 assignments
- report: `tested / NON_CLAIM_TEST_ARTIFACT`
- scientific claim authorization: `false`
- context analysis: `BLOCKED_NO_FROZEN_CONTEXT_RULE`
- Pair response-pattern labeling: `BLOCKED_NO_FROZEN_PREDICATE`

## Remaining prospective gate

The implementation can consume frozen representation and study inputs, but
the active protocol remains `SPECIFIED_DRAFT`. Prompt TSG extraction, role
allocation, D0 census, and provider execution remain disabled until the joint
author decision in
`docs/superpowers/phase0/parameter_qualification_register.md` is approved and
qualified. On 2026-09-02 the author selected Beijing Alibaba Bailian
`qwen3.7-flash-2026-07-15` as the fixed snapshot for every prospective external
LLM call, with no dynamic alias, fallback, replication model, or automatic
retry. That closes model/provider identity only. The Flash functional judge and
all other assigned roles still require prospective qualification, and the
unresolved joint block still includes practical margins, RQ1 comparator set,
K ceilings, alpha, target power, realization/request-slot counts, final token
ceilings, and the formal total cost ceiling. On 2026-09-02 the author separately
approved a CNY 100 ceiling for non-confirmatory preexperiment and qualification
work. That limited authorization does not activate the formal protocol or
permit exploratory evidence to be promoted into Confirmation.
