# Randomized confirmation migration

This is a breaking migration from the historical paired, two-arm confirmation workflow to the
M5 randomized prompt-confirmation protocol. Existing two-arm run directories are not upgraded in
place. Start a fresh run directory and regenerate every stage from `extract-prompt-tsg` through
`run-oracle --condition confirmation`.

## Frozen pre-randomization contract

Source prompt roles are pre-attested, pre-outcome inputs. A confirm task uses exact
positive/neutral counterparts: each variant role names the exact neutral baseline prompt and binds
the prompt bytes, clause range, feature catalog, task, CWE, and the single contrast-owner
operation. Forward and reverse audit views share one contrast identity; only the attested owner
operation is assignable, so one prompt pair is never counted twice.

`SecurityNeutralPromptInvariant` applies before assignment. Task wording must remain neutral about
whether an implementation contains a vulnerability and must not reveal or predict the independent
Oracle result. Every arm has a per-arm AllowedDelta (`AllowedDelta`): the target arm may change only its selected
feature, a no-op rewrite may change presentation without changing task or safety semantics, a
length-matched placebo may change only its registered placebo surface, and a generic security
reminder may add only its registered generic safety feature. Safety feature add/remove and task
feature add/remove are expressed as finite target operations; they do not create an unbounded rule
language.

A hard pre-randomization exclusion is different from diagnostics. A task-protocol block is
excluded before randomization when its complete arm set, provenance, neutral wording, exact
counterpart relation, or `AllowedDelta` validation fails. After assignment, `target_changed` and
semantic validity are diagnostics; they do not delete assigned observations or filter the primary
ITT population.

Both `text-native` and `graph-native` modes publish the same typed protocol and validation
artifacts. Text-native execution edits the submitted prompt directly. Graph-native execution
applies a typed graph patch and renders the resulting prompt before the same independent blind
extraction and validation gates. The LLM executor simplifying assumption treats a configured LLM
as the intervention executor, not as an outcome judge. Its request, decoding coordinates, system
template, schema, and response are provenance-bound. A deterministic executor remains available.
The separate extractor role receives only prompt identity, task identity, prompt text, and its
finite catalog; it never receives arm or target labels, and its system template is distinct from
the executor template.

## Randomization, generation, and commit point

Only complete blocks enter randomization. Each block contains the exact protocol arm set for one
task-bound protocol. Configured confirmation seed slots are sorted and frozen before assignment;
each slot receives exactly one arm by the versioned deterministic randomizer. The assignment commit
point is the atomic publication of both
`interventions/randomization_manifest.jsonl` and `interventions/assignments.jsonl` plus the
`randomize-confirmation` manifest. Once this commit exists, generation consumes it as-is: it does
not redraw arms, replace failed assignments, or use outcomes to choose a prompt.

Each assignment publishes one terminal execution record. Successful generation also publishes one
canonical code record. Terminal-no-code handling keeps a failed or otherwise terminal assignment
in the committed experiment with no fabricated code and no Oracle row. Later ITT analysis retains
that assignment according to the preregistered outcome policy; it is not silently removed.

Provider-result policy v2 recognizes two authenticated terminal-no-code reasons. `content_filter`
requires an empty provider content field. `token_limit` requires the standard
`finish_reason=length`, a configured single token-limit parameter, and reported completion-token
usage exactly equal to that frozen limit. The partial response is retained only in the protected
transport artifact and bound by digest; it is not imported as code, retried until favorable, sent
to the functional judge, or evaluated by the Oracle. Any other finish reason or a mismatched usage
count remains an invalid provider response and fails closed.

The M5 CLI sequence is:

```text
extract-prompt-tsg
generate observed code
run-oracle --condition observed
discover
build-confirmation-variants
randomize-confirmation
generate-confirmation
run-oracle --condition confirmation
```

`run-all` executes that sequence and stops after the committed confirmation Oracle. Pairing,
effect estimation, JCI analysis, and reporting belong to M6 and cannot publish during M5.

A valid terminal Oracle plus its stage manifest marks a completed run. The completed run is
immutable: a later `run-all` first validates the complete committed chain and then exits without
calling a generation provider or analyzer. `run-all --force` cannot overwrite, rebuild, or delete
that commit and fails closed with instructions to start a new run directory. Partial, tampered,
untrusted, or future-artifact states are rejected before this immutable-completion decision for
both forced and unforced invocations.

## Removed two-arm artifacts and commands

The `intervene` and `generate-counterfactual` commands are no longer registered with Typer. They
must not be used to continue an old run. Historical two-arm artifacts are not accepted as M5
inputs, including:

- `interventions/interventions.jsonl` and `interventions/paired_prompts.jsonl`;
- `generation/counterfactual_requests.jsonl`, `generation/counterfactual_code.jsonl`, and their
  two-arm generation manifests;
- `oracle/counterfactual_oracle.jsonl` and the paired `confirm` Oracle contract;
- `analysis/pair_results.jsonl`, `analysis/hypothesis_effects.jsonl`, and historical reports.

The replacement artifacts are the frozen target/protocol/variant bundle, randomization manifest,
assignments, confirmation request/execution/code bundle, and
`oracle/confirmation_oracle.jsonl`, each with a committed stage manifest and complete provenance.
Legacy schema 1.0/1.1 counterfactual records are rejected explicitly rather than guessed or
silently converted.
