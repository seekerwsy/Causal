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

## Approved live calibration result

The approved bounded run is preserved under
`runs/e2e-pilot/extractor-calibration-cwe78-v1-live-20260815-01`. It ran on host
`DESKTOP-ES5QORS`, from the dataset-audit worktree, with the fixed project Python 3.12
environment. The artifact manifest binds the effective application and calibration configurations,
command, environment, inputs, raw requests, raw responses, proposals, graphs, records, failures, and
report by SHA-256.

The run completed all six planned provider attempts and received all six responses. There are no
pending calls and no semantic retries:

| Strategy | Cases passed | Feature decisions | Execution errors |
| --- | ---: | ---: | ---: |
| `llm_facts_criteria_v2` | 3/3 | 18/18 | 0 |
| `llm_direct_graph_criteria_v2` | 0/3 | not scored | 3 |
| `deterministic_catalog_v1` | 3/3 | 18/18 | 0 |

The facts strategy correctly separates the command-execution task, the explicit no-shell/list-
arguments mechanism, and the generic reminder. It also produces no false positives on the three
sentinel features. This is the first strategy that fixes the observed Gate B measurement failure
without changing the intervention or adding a new phrase-specific deterministic rule.

## Direct-graph failure diagnosis

The direct-graph responses selected the semantically correct feature sets in all three contrasts:

- task only: `task.process_launch`;
- target mechanism: `task.process_launch` and `safety.safe_subprocess`;
- generic reminder: `task.process_launch` and `safety.generic_security_reminder`.

They were nevertheless rejected before scoring because their evidence objects violated the frozen
strict response contract. Across the responses, the model renamed required fields to variants such
as `substring`, `hash`, `start_offset`, and `end_offset`, and supplied non-verifiable digest values.
The validator correctly failed closed. These are serialization and evidence-provenance failures,
not evidence that the model chose the wrong feature semantics.

This records a concrete design lesson: an LLM should not be responsible for semantic selection,
typed graph closure, exact character offsets, and cryptographic digests in one step. Any follow-up
direct-graph variant should accept only a unique exact quote from the model and reuse the existing
facts-path normalization boundary to derive offsets and SHA-256 locally before strict graph
validation. The failed responses remain immutable; no same-run repair or provider retry was made.

## Current decision

`llm_facts_criteria_v2` is the preferred candidate. The result is an engineering calibration only,
so it does not yet authorize Gate B or a scientific comparison claim. Following the frozen decision
rule, the next step is an independent CWE-78/CWE-89 calibration extension with new prompts. Only if
that extension passes should the extractor be integrated and the complete ten-Prompt Gate B set be
re-extracted. The deterministic catalog remains a fallback, and the direct-graph strategy remains an
experimental alternative pending the smaller deterministic evidence-boundary revision described
above.
