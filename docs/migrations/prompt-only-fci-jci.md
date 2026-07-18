# Prompt-only FCI/JCI migration

This is a breaking migration to the final Prompt-only causal boundary. Existing run directories
whose manifests or artifacts predate this contract must not be upgraded in place.

SecAware supports Python 3.12 patch releases only (`>=3.12,<3.13`).

## Non-negotiable analysis boundary

Prompt TSG edges encode semantic extraction and validation relationships; they are not causal edges and are never supplied to FCI, JCI, or RFCI as causal adjacencies.

PAG circle endpoints remain circles: no report, path query, JCI constraint, or RFCI sensitivity run may silently orient them.

Randomized ITT is the primary confirmatory estimate.

JCI is secondary and cannot alter, replace, filter, or select the randomized ITT or the frozen hypotheses.

RFCI is optional, requires the pinned Java/JPype/py-tetrad runtime, and cannot block or redefine the primary ITT result when unavailable.

RFCI v2 declares `exclude_selection_bias=true` and sets Tetrad's
`excludeSelectionBias=true` parameter before search. This no-selection-bias assumption makes Tetrad
apply the declared background-knowledge orientation inside RFCI. It is confined to the optional
sensitivity backend and does not alter causal-learn FCI, the frozen hypotheses, or randomized ITT.
The persisted graph is Tetrad's original PAG serialized through the shared endpoint codec: no local
post-processing rewrites circle endpoints into arrows or relaxes background-knowledge validation.

Generated code is consumed only by the independent Oracle and an explicitly configured functional evaluator; it is never a causal variable.

Missing, invalid, or unavailable functional evaluation is `unknown`/`non-evaluable`, never a negative outcome.

Best/worst-case bounds retain every randomized assignment and cannot be replaced by complete-case filtering.

Pre-randomization exclusions occur before assignment and are recorded separately; post-assignment failures remain in the assigned ITT arm.

The Oracle security outcome and any preregistered functional outcome are separate typed outcomes.
Prompt text features, execution mode, provider identity, generated code, analyzer findings, and
functional evidence do not become causal graph nodes merely because their provenance is retained.

## Interpretation and stage order

FCI operates on the declared Prompt-side causal-variable table. Frozen hypotheses are committed
before confirmation variants or assignments exist. Complete-block randomization fixes the ITT
universe. The primary effect stage therefore keeps terminal-no-code, Oracle failure, and functional
non-evaluation records in the denominator and reports the declared sensitivity bounds.

JCI consumes the already frozen experiment and emits raw PAGs, declared background knowledge,
constrained PAGs, and assumption-set orientation deltas. JCI orientation deltas are attributed only to the complete declared assumption set; they cannot be attributed to any individual assumption.
Those deltas are secondary diagnostics, not edits to the FCI artifacts or hypothesis set. RFCI is
likewise a sensitivity product. Its capability record distinguishes disabled, unavailable, and
available execution; the base install does not import Java, JPype, or py-tetrad.

Run configuration and inputs should be checked before creating a run:

```bash
secaware preflight --config configs/demo.yaml
```

If a frozen protocol declares a functional evaluator, import its independently produced results
before resuming `run-all`:

```bash
secaware import-functional-outcomes \
  --config configs/demo.yaml \
  --run-dir runs/demo \
  --results functional-results.jsonl
secaware run-all --config configs/demo.yaml --run-dir runs/demo
```

## Digests and regeneration

Every committed output below is authenticated by its stage manifest's `output_sha256`; record-level IDs and `*_sha256` fields bind semantic content and upstream provenance.

In particular, Prompt extraction binds the catalog and extractor policy; FCI records bind table,
configuration, background-knowledge, bootstrap, path, and freeze digests; randomization binds
`randomization_plan_sha256` and `assignments_sha256`; generation binds request, provider, policy,
usage, and code digests; functional records bind evaluator policy and evidence; ITT records bind
the assignment universe, target-instance universe, and bootstrap manifest; JCI deltas bind their
assumption set; and RFCI capability provenance binds the optional runtime and Tetrad JAR digest.
RFCI v2 PAG provenance additionally binds the strict `exclude_selection_bias=true` configuration,
and the RFCI stage contract names that dependency explicitly. Existing v1 run directories cannot be
upgraded in place; run v2 in a new directory so both provenance chains remain separately auditable.
The nine report outputs preserve those source identifiers and digests rather than recomputing or
mutating producer artifacts.

To regenerate, start a new run directory and rerun `secaware run-all`; never delete, edit, or overwrite a sealed artifact or its `.stages/<stage>.json` manifest in a completed run.

A valid completed report is immutable. A rerun without `--force` authenticates and reuses it;
`run-all --force` is rejected. Changed inputs, configuration, code, policy, catalog, functional
evidence, or optional RFCI capability require a new run directory so old and new provenance remain
separately auditable.

## Complete committed-output inventory

The observed request and attempt journals are emitted by the OpenAI-compatible provider path;
`generation/observed_code.jsonl` is the canonical observed code output for every provider. RFCI
files are always present as typed capability/result/failure outputs even when RFCI is disabled or
unavailable. The report transaction publishes exactly the final nine `reports/` files.

<!-- artifact-inventory:start -->
- `tsg/prompt_extraction_proposals.jsonl`
- `tsg/prompt_tsg.jsonl`
- `generation/observed_requests.jsonl`
- `generation/observed_code.jsonl`
- `generation/observed_attempts.jsonl`
- `oracle/observed_oracle.jsonl`
- `discovery/causal_tables.jsonl`
- `discovery/causal_observations.jsonl`
- `discovery/causal_exclusions.jsonl`
- `discovery/background_knowledge.jsonl`
- `discovery/reference_pags.jsonl`
- `discovery/bootstrap_draws.jsonl`
- `discovery/bootstrap_pags.jsonl`
- `discovery/bootstrap_failures.jsonl`
- `discovery/path_support.jsonl`
- `discovery/hypotheses_frozen.jsonl`
- `discovery/discovery_failures.jsonl`
- `interventions/target_specs.jsonl`
- `interventions/target_instances.jsonl`
- `interventions/confirmation_protocols.jsonl`
- `interventions/confirmation_protocol_instances.jsonl`
- `interventions/intended_patches.jsonl`
- `interventions/variant_extraction_proposals.jsonl`
- `interventions/variant_prompt_tsg.jsonl`
- `interventions/graph_deltas.jsonl`
- `interventions/prompt_variants.jsonl`
- `interventions/length_matches.jsonl`
- `interventions/pre_randomization_exclusions.jsonl`
- `interventions/randomization_manifest.jsonl`
- `interventions/assignments.jsonl`
- `generation/confirmation_requests.jsonl`
- `generation/confirmation_execution.jsonl`
- `generation/confirmation_code.jsonl`
- `oracle/confirmation_oracle.jsonl`
- `analysis/functional_outcomes.jsonl`
- `analysis/assignment_outcomes.jsonl`
- `analysis/contrast_specs.jsonl`
- `analysis/effect_bootstrap_draws.jsonl`
- `analysis/itt_effects.jsonl`
- `analysis/effect_failures.jsonl`
- `analysis/jci_tables.jsonl`
- `analysis/jci_observations.jsonl`
- `analysis/jci_raw_pags.jsonl`
- `analysis/jci_background_knowledge.jsonl`
- `analysis/jci_constrained_pags.jsonl`
- `analysis/jci_orientation_deltas.jsonl`
- `analysis/jci_failures.jsonl`
- `analysis/rfci_capability.jsonl`
- `analysis/rfci_pags.jsonl`
- `analysis/rfci_failures.jsonl`
- `reports/discovery_pags.jsonl`
- `reports/hypotheses.jsonl`
- `reports/interventions.jsonl`
- `reports/assignments.jsonl`
- `reports/effects.csv`
- `reports/jci_orientations.csv`
- `reports/failures.csv`
- `reports/hypothesis_cards.jsonl`
- `reports/summary.md`
<!-- artifact-inventory:end -->

## Removed compatibility surface

The final CLI exposes only the explicit observed, Oracle, discovery, randomized confirmation,
analysis, and report stages. Generic generation/oracle aliases, heuristic discovery, two-arm
counterfactual intervention, legacy effect/pairing schemas, and reporting compatibility wrappers
are not accepted. Convert source inputs into the current schemas and begin a new run rather than
importing old manifests or inferred legacy artifacts.
