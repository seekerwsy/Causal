# Extractor Improvement Calibration v1

## Status and purpose

This is a bounded engineering calibration, not a paper benchmark and not evidence for a causal or
security-effect claim. It addresses the observed CWE-78 Gate B measurement failure without changing
the intervention, overriding a blind graph, or adding a phrase-specific production rule.

## Frozen inputs

Three synthetic, security-neutral CWE-78 minimal contrasts are independent of the discovery and
confirmation task pools:

1. command-execution task only;
2. the same task with an explicit list-arguments/no-shell requirement;
3. the same task with only a generic security reminder.

The expected state table covers `task.process_launch`, `safety.safe_subprocess`,
`safety.generic_security_reminder`, and the three leakage/unsafe sentinels. The exact inputs and
expectations are versioned under `data/e2e-pilot/extractor-calibration-cwe78-v1/`.

## Strategies

- `llm_facts_criteria_v2`: structured feature-state facts followed by the deterministic TSG builder.
  The request exposes the finite reviewed FeatureSpec terms and intervention clauses as semantic
  criteria and explicitly separates task operations, generic reminders, and target mechanisms.
- `llm_direct_graph_criteria_v2`: the same finite semantic criteria are attached to the typed node
  templates, while the LLM emits the complete local graph subject to the existing strict parser.
- `deterministic_catalog_v1`: the existing offline catalog extractor, retained as a baseline and
  fallback rather than expanded with new rules.

Both LLM strategies use the same `qwen3.5-flash-2026-02-23` provider coordinates, temperature zero,
one attempt, and one response per prompt. The frozen budget is six provider calls. No semantic retry,
model comparison, code generation, Oracle, or Gate B mutation is allowed in this calibration.

## Decision rule

The first screen is exact correctness on all three cases and all expected feature states, with zero
parser/graph errors and zero sentinel false positives. If several strategies pass, structured facts
plus deterministic construction remains preferred because it exposes a smaller LLM-controlled
surface. A failing strategy is retained as evidence and is not repaired on the same calibration run.

No strategy is admitted into Gate B from these three cases alone. A promising strategy must next be
frozen and checked on an independent CWE-78/CWE-89 calibration extension before the complete ten-
Prompt Gate B re-extraction.

## Zero-provider preflight

`runs/e2e-pilot/extractor-calibration-cwe78-v1-plan-20260815-02` validated all inputs and generated
the exact six planned request artifacts. Every request contains the finite semantic-criteria
projection and Prompt text, and none contains an outcome, Oracle result, or experiment label. The
deterministic baseline passed all 18 expected feature-state decisions. No provider call was made.
