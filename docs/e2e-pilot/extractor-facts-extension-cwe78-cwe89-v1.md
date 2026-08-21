# Extractor Facts Extension CWE-78/CWE-89 v1

## Purpose

This is the independent extension required by the first extractor-improvement calibration. It tests
whether `llm_facts_criteria_v2` generalizes beyond the original CWE-78 wording and transfers to
CWE-89 before any production integration or complete Gate B re-extraction. It is a bounded
engineering calibration, not a paper benchmark or causal-effect result.

## Frozen design

The extension contains six new synthetic, security-neutral Prompts that are not members of the
discover or confirm pools:

- CWE-78: task only, semantically paraphrased target mechanism, and generic reminder;
- CWE-89: task only, semantically paraphrased target mechanism, and generic reminder.

The target variants specify mechanisms without claiming that the task or any implementation is
vulnerable. The generic variants do not identify a CWE or target mechanism. No Prompt includes an
Oracle result, expected label, experiment arm, or generated code.

The LLM strategy returns finite feature-state facts plus unique exact evidence quotes. The existing
deterministic builder derives the typed graph and evidence provenance. The unchanged deterministic
catalog is retained as a diagnostic baseline; no new detection terms are added for this extension.

The model and transport coordinates remain `qwen3.5-flash-2026-02-23`, temperature zero, one attempt,
and one response per Prompt. Only `llm_facts_criteria_v2` uses the provider, so the frozen live-call
budget is six. Direct graph extraction, semantic retries, code generation, Oracles, and Gate C are
out of scope.

## Admission rule

The facts strategy must pass all six Prompts and all 36 expected feature-state decisions with zero
parser errors and zero sentinel false positives. The deterministic baseline is diagnostic and is not
an admission requirement because the new wording intentionally tests semantic generalization beyond
literal catalog terms.

Passing this extension authorizes implementation of the same semantic-criteria projection in the
production facts extractor, followed by a zero-provider request audit and the complete ten-Prompt
Gate B re-extraction. It does not authorize Gate C or a scientific comparison claim.

## Zero-provider preflight

`runs/e2e-pilot/extractor-facts-extension-cwe78-cwe89-v1-plan-20260815-01` completed
without a provider attempt. It froze six planned facts requests and recorded the effective
configuration, command, environment, request payloads, deterministic proposals and graphs, records,
report, and artifact manifest.

The request audit found:

- six requests for six independent Prompts, with zero exact Prompt overlap against existing
  `data/e2e-pilot` JSONL assets;
- all ten applicable finite feature entries in every request carry FeatureSpec-derived semantic
  criteria;
- zero Oracle, expected-result, outcome, experiment-arm, or generated-code fields;
- a frozen budget of six provider calls, with temperature zero, one attempt, and no semantic retry.

The deterministic catalog produced no execution errors or false-positive sentinel states, but it
missed all six paraphrased task features plus the two target mechanisms and two generic reminders:
26/36 expected decisions were correct. This is diagnostic rather than an admission failure; it
confirms that the extension exercises semantic generalization instead of the original literal terms.

The selectable-strategy runner change also passed a zero-provider compatibility plan using the
original three-strategy CWE-78 configuration. It generated the same six planned LLM requests and the
deterministic baseline again passed 18/18 decisions.

## Approved live result

The approved live run is preserved under
`runs/e2e-pilot/extractor-facts-extension-cwe78-cwe89-v1-live-20260815-01`. All six
planned provider calls were attempted exactly once and all six received responses. There were no
retries, pending calls, failure artifacts, parse errors, or graph-validation errors. The manifest
binds 20 effective-configuration, command, environment, raw request, raw response, proposal, graph,
record, and report artifacts by SHA-256.

`llm_facts_criteria_v2` passed all six independent Prompts and all 36 expected feature-state
decisions. In both CWE scopes it correctly distinguished the task-only Prompt, the semantically
paraphrased target mechanism, and the generic security reminder. All prohibited-request,
vulnerability-disclosure, and expected-outcome-leakage sentinels remained absent.

The deterministic catalog remained at 26/36 decisions, with ten false negatives and no execution
errors: all six paraphrased task features, both target mechanisms, and both generic reminders were
missed. No catalog term or extraction rule was changed. The contrast therefore supports the
engineering decision that FeatureSpec-derived semantic criteria address the observed measurement
failure without adding a new literal phrase rule.

The frozen admission rule is satisfied. This authorizes production integration of the same facts
request projection and a zero-provider request audit before the complete ten-Prompt Gate B
re-extraction. It still does not authorize Gate C or a scientific performance claim.

## Production integration

The admitted projection is integrated into the existing `llm_facts_v1` backend rather than exposed
as a second production extractor. Applicable catalog entries now carry FeatureSpec-derived positive
indicators, reviewed requirement clauses, and an explicit-state rule. The system contract separates
task operations, target-specific mechanisms, and generic reminders. The projection version is bound
into the extractor policy digest, while the catalog digest already binds the underlying terms and
clauses.

The response boundary is unchanged: the model returns only complete feature-state facts and unique
exact Prompt quotes; deterministic code derives offsets and SHA-256 values, validates the proposal,
and builds the typed graph. Invalid structure, incomplete feature coverage, fabricated or non-unique
evidence, and policy drift still fail closed without semantic retry.

Targeted verification passed 12 facts-backend tests and 78 adjacent factory, Prompt TSG pipeline,
and extraction-security tests. No full-suite or provider call was used for this integration check.
