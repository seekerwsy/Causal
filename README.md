# Prompt Mechanism Study

Prompt Mechanism Study is a reviewable research artifact for testing whether a
prospectively frozen prompt intervention changes Oracle-evaluable secure-code
yield while preserving functionality. It is not a deployment or campaign
platform.

The normative design is the
[context-conditioned intervention policy framework](docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).
The [reviewer guide](docs/reviewer-guide.md) maps that design to the active
entry point, artifacts, implementation, and verification commands.

## One active method

The method is one linear, seven-stage path:

```text
source records
  -> representation as deduplicated task units and Prompt TSGs
  -> outcome-blind prioritization
  -> prospective hypothesis and adapter freeze
  -> complete-block intervention and randomization
  -> independent code, security, and functionality measurement
  -> total assigned-arm outcome ledger
  -> task-unit ITT inference and independently verified report
```

1. **Representation** normalizes source records, forms conservative task
   units, chooses one representative prompt per unit, and extracts bounded
   Prompt TSG facts.
2. **Prioritization** audits feature support and source overlap before running
   family-local selectors. Outcomes are unavailable at this stage.
3. **Hypothesis freeze** binds the task population, Prompt TSG evidence,
   mechanism or pair, exact prompt variants, adapters, seeds, endpoints,
   estimands, and multiplicity rules.
4. **Intervention and randomization** materializes ADD/REMOVE arms or a complete
   `2 x 2` pair block and freezes every assignment before generation.
5. **Measurement** generates code, checks validity, evaluates the local
   Security Oracle, and asks the blinded Functional Judge against the frozen
   contract.
6. **Outcome assembly** accounts for every assigned unit. Invalid, insecure,
   unknown, failed, and non-functional outcomes are retained.
7. **Inference and reporting** estimates assigned-arm ITT with equally weighted
   task units, reports unknown bounds, applies the frozen simultaneous
   inference rules, and writes a replayable result bundle.

A **task unit** is the independent, cross-source-deduplicated unit. Older
frozen files retain physical fields such as `semantic_cluster_id`; those names
are immutable coordinates, not a second analysis unit. A **Prompt TSG** is a
typed semantic representation of the prompt. Its edges are not causal edges,
and generated code is neither a primary-PAG variable nor a causal mediator.

## Intervention families

An atomic ADD or REMOVE hypothesis has Target, operation-matched No-op,
Placebo/Sham, and Generic roles. Target versus No-op is the confirmatory
contrast; the other roles diagnose specificity. Post-assignment fidelity and
non-target drift never filter the ITT denominator.

The pairwise extension uses a complete block:

```text
A00 = No-op 1 + No-op 2
A10 = Target 1 + No-op 2
A01 = No-op 1 + Target 2
A11 = Target 1 + Target 2
```

Its primary interaction is `mu11 - mu10 - mu01 + mu00`. Every supported
task-unit/realization/model coordinate contains all four assigned cells.
Functionality non-inferiority can authorize a practical-success claim only if
its study-specific power qualification was frozen before outcomes and its
simultaneous lower bound clears the frozen margin.

## Outcomes and claim boundary

The prospective primary safety outcome is Oracle-evaluable secure-code yield.
It remains separate from:

- code validity;
- Oracle support and evaluability;
- unknown coverage among valid code;
- functionality;
- joint secure-and-functional success.

The Security Oracle preserves `unknown`; unknown is never promoted to secure.
The Functional Judge combines local syntax/compilation checks with blinded
review of a frozen functional contract and is not presented as executable test
coverage. Demo, smoke, calibration, and development-canary outputs are never
confirmatory evidence.

The active successor and schema-1.1 factorial implementations are specified,
implemented, and reviewer-tested, but a new claim-bearing provider run has not
yet been reported under them. The tracked schema-1.0 factorial bundles remain
historical formal evidence and are independently replayable; they are not
migrated or reinterpreted as active-protocol results:

- [controlled from-scratch null result](docs/experiments/2026-08-27-factorial-sql-confirm-v3-results.md);
- [bounded scaffold-repair follow-up](docs/experiments/2026-08-27-factorial-sql-scaffold-repair-v1-results.md).

## Entry point and reproduction

The package installs one command: `prompt-mechanism-study`. Its subcommands are
explicit stage boundaries in the same method:

```text
prompt-mechanism-study selector-study --help
prompt-mechanism-study interaction-selector --help
prompt-mechanism-study successor-experiment --help
prompt-mechanism-study factorial-experiment --help
```

An active factorial run requires a separately verified pre-outcome freeze:

```text
prompt-mechanism-study factorial-experiment freeze FREEZE \
  --repository-root . --config ACTIVE_SCHEMA_1_1_CONFIG

prompt-mechanism-study factorial-experiment run RESULT \
  --repository-root . --config ACTIVE_SCHEMA_1_1_CONFIG --freeze FREEZE
```

Exact-byte bundle verification and independent scientific replay are distinct:

```text
prompt-mechanism-study verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3

prompt-mechanism-study factorial-experiment verify \
  data/formal/results/factorial-sql-confirm-qwen35-v3
```

Run the maintained reviewer invariant suite only when needed:

```text
python -m pytest -q
```

After a method-level change, the smallest zero-network active-path reproduction
is:

```text
python -m pytest -q -m milestone tests/test_factorial_reviewer_smoke.py
```

It closes 16 assignments through freeze, generation fixtures, the real local
Security Oracle, outcome assembly, inference, and independent verification.
It writes only temporary artifacts and has `scientific_claim_allowed=false`.

Historical execution code is kept in Git history and historical result bundles,
not as a second live runner. Deployment incidents, provider tuning, calibration
exploration, temporary checkpoints, and unrelated corpora are outside the
default reviewer path.
