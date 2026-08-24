# Context-conditioned mechanism validation

## Result and evidence level

The engineering validation gate passed on commit
`c1b6148cf43df10278291923c327a55b04cbda6e`. The run validates the frozen
task-context binding and the text-level four-arm intervention contract. It does not generate code,
invoke either outcome Oracle, estimate an effect, or authorize a scientific claim.

The active execution is the only accepted result:

- deployment: `/home/wsy/prompt-mechanism-study-deployments/context-conditioned-mechanism-validation-c1b6148-20260825-04`;
- execution: `/home/wsy/prompt-mechanism-study-experiments/context-conditioned-mechanism-validation-c1b6148-20260825-04`;
- source archive SHA-256: `9c8950f54b6b5c611d903c724330a199c72ef38bacdc8c85fb07b83cc878ed28`;
- validation-summary SHA-256: `1d0634a47812bb018bacd9cad99e12f536dde66d776fc9ad41b90d1623ef6841`;
- execution manifest: 75 files, independently rechecked with zero mismatches;
- deployment and execution roots were made read-only after closure.

## Change being validated

The mechanism registry remains task-independent, but each realization now declares the context in
which it is applicable, its required delta, prohibited changes, preserved behavior, and Oracle
profile. A separate outcome-blind binding maps a task to one compatible realization before
randomization. The executor receives only that bounded task-specific contract, and an independent
LLM validator checks Specific, Generic, and Placebo text against the source prompt and functional
requirements.

The validation exposed one real modeling defect before the accepted run: a fixed-origin SSRF rule
conflicted with a task that requires valid user subdomains beneath a trusted domain. The repair was
a distinct `cwe918_trusted_domain_subdomain` realization; the validator was not weakened.

## Frozen inputs

- config: `d54dff48d3a98a568057dc6b19937b093e1b83cfaec1a57903b3f6c759ca214c`;
- 12 source tasks: `dedcdab3cff76b2ebf5494e24bb09b99043dd632ec3083e057d4c75f488ffb2b`;
- context bindings: `d92f4fd6d625e5f2b8fca6a592e0f256d4d46b2c13582653653b8852f60f159c`;
- 7 eligible tasks: `edbeb05f98bff7a3cdfd83da4e0a318ead5fe82e1eccde63f81937d8df6d93d6`;
- mechanism registry: `2f70e348d1947891efc6debb81495c66cb255095714bd73d442e442dcb47a85e`.

Binding used no arm, generated code, Oracle output, or experiment outcome. Seven tasks were
applicable: three CWE-22, two CWE-89, and two CWE-918. Five were excluded before provider calls
because their required behavior had no compatible mechanism realization: arbitrary SQL
identifiers, arbitrary paths, arbitrary origins, or no untrusted SQL input.

## Execution and checks

The run used `qwen3.5-flash-2026-02-23` as intervention executor and non-thinking
`qwen3.7-max-2026-05-20` as blind semantic validator, both at temperature zero. It ran on
`ubuntu-22` with Python 3.12.13; the host has two NVIDIA A800 80 GB GPUs, although model inference
was through the Bailian HTTPS API.

- zero-call preflight: passed;
- pilot: 5/5 tasks passed, 10 provider calls;
- remaining: 2/2 tasks passed, 4 provider calls;
- total: 7/7 unique eligible tasks, 14 provider calls, zero errors;
- all Specific, Generic, and Placebo validation flags were true;
- executed and eligible task IDs matched exactly;
- zero not-applicable tasks were sent to the provider;
- no generation, Security Oracle, Functional Oracle, outcome, or inference file was present.

Three prior deployment tags are retained only as excluded engineering attempts. Together they used
six provider call attempts while exposing a Python-version mismatch, a response-preservation defect,
and the trusted-subdomain contract conflict. They are not pooled with the accepted validation.

## Claim boundary and next gate

This result establishes that the revised intervention layer is applicable only where its declared
preconditions hold and that its three active suffixes preserve the source task contract at the
text-review level on this small representative set. It does not establish generated-code security,
functionality, or a causal effect. The next scientific step is a new prospectively frozen,
outcome-unseen four-arm study using disjoint tasks; this validation set remains engineering-only.
