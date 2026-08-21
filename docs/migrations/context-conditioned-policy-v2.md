# Context-conditioned policy v2 migration boundary

This is a breaking, prospective protocol boundary. A completed legacy run is
never edited, relabeled, or promoted into Phase 0+ evidence. New work must use a
new run directory and declare the v2 protocol root before outcomes exist.

## What may be reused

A Prompt TSG 2.1 artifact may be read again only when its task, exact Prompt,
extractor, catalog, schema, and policy digests all match the new source
inventory. The new context and actionable-feature queries are then evaluated
again and produce new query-evidence records. Old motif columns and old path
freezes are not reused.

Exact natural-generation, code, Oracle, and functional records may be
reassembled only when every v2 coordinate and producer digest is authenticated.
This reassembly creates new v2 receipts; it does not modify the source records.

## What must be regenerated

The following are always regenerated under a new outcome-blind v2 protocol:

- natural query results and causal tables;
- candidate and selector freezes;
- intervention bridges, global realization specifications, and task bundles;
- prompt variants, assignments, outcomes, and analyses.

Legacy confirmation outcomes cannot become multi-realization evidence because
their `Q_h`, task bundles, common-support populations, and randomized assignment
universe were not committed prospectively.

## Atomic operation rule

A v2 hypothesis contains exactly one operation. A legacy hypothesis permitting
both ADD and REMOVE is rejected as a combined-operation artifact; it is never
split into two v2 hypotheses and never coerced to one preferred operation after
outcomes are known. A single-operation legacy hypothesis is also not upgraded:
it must be rebuilt from outcome-blind source artifacts in a new run.

`LegacyHypothesisMigrationDecisionV2` records the source artifact digest and the
versioned migration-rule digest. `reject_legacy_hypothesis_upgrade` is the
fail-closed boundary used whenever a caller attempts to turn that decision into
formal v2 evidence. Both functions are pure and have no filesystem publication
surface.

## Reader and directory isolation

Legacy readers accept only their declared v1 schema versions and reject v2
generation, hypothesis, and outcome records. Conversely, v2 records use new
classes and content-address namespaces; a required legacy `seed_id` is never
reinterpreted as `request_randomness_slot`, and nullable `provider_seed` exists
only in the v2 coordinate chain.

Migration assessment never writes a run directory. Any later stage publication
must use the repository's immutable new-run transaction and must fail if the
destination already exists. The original run remains the authoritative source
for all legacy results.
