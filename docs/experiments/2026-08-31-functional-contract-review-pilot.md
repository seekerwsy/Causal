# Functional-contract review pilot

## Purpose and evidence boundary

This outcome-blind pilot tested whether one strong LLM review could automatically
qualify the 2,165 extracted functional contracts. The reviewer saw only the source
prompt, language, and proposed contract. It did not receive CWE labels, arms,
generated programs, Oracle outputs, or experiment outcomes. The first 25 contracts
by ascending `cluster_id` were used while the policy was developed and are recorded
in `data/dataset-curation/contract-review-development-exclusions-v1.json`.

The pilot is method-development evidence, not confirmatory dataset evidence. Those
25 task units must not enter a future confirmation sample merely on the basis of
this tuned reviewer output.

## Findings

The final pilot response closed all 25 rows. A direct case review classified six
contracts as materially faulty: three leaked response-format instructions into the
software behavior contract, one invented an HTML-package requirement, one omitted
an implied context/template input, and one omitted the incomplete `remove_user`
entrypoint entirely.

Against those case decisions, the LLM marked six contracts faulty, with four true
positives, two false positives, and two false negatives. Fault-detection precision
and recall were therefore both 4/6 on this development set. This is insufficient
for an automatic admission gate. The model output is retained only as triage;
`faithful` cannot be interpreted as independently verified semantic quality.

A deterministic scan of the complete 2,165-contract bundle found 71 contracts whose
requirements contain code-response formatting such as “return only the code without
preamble or suffix.” These are contract defects even when the underlying benchmark
task remains usable. They should be repaired in a successor contract bundle, not
used to exclude the source task.

## Consequence

The active review command freezes three distinct facts:

1. deterministic identity, prompt-hash, and response-format-leak checks;
2. an LLM fidelity/evaluability triage result for every contract; and
3. a reviewer-qualified candidate subset.

It explicitly sets `semantic_quality_established=false` and
`final_experiment_eligibility_established=false`. Final admission additionally
requires independent adjudication of the experiment-eligible subset and the
separate language/runtime, Prompt TSG, MechanismSpec, and Security-Oracle gates.
