# Prompt Mechanism Study

Prompt Mechanism Study is a reviewable research prototype for testing whether a
prospectively frozen prompt policy changes Oracle-evaluable secure-code yield
while preserving functionality. It is not a deployment platform.

The normative method is
[the context-conditioned intervention-policy framework](docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).
Its active protocol is `phase-context-policy-v3`, currently
`SPECIFIED_DRAFT`: the method core is implemented and tested, but no formal
discovery, provider confirmation, or claim-bearing schema-3 result exists.

## One active path

The repository exposes one schema-3 path:

```text
representation
  -> prioritization
  -> hypothesis freeze
  -> intervention/randomization
  -> measurement
  -> outcome assembly
  -> inference/reporting
```

The path preserves these boundaries:

- Prompt TSG facts describe prompt semantics; they are not causal edges.
- A task unit is the independent, cross-source-deduplicated analysis unit.
- After representation qualification, an optional pre-Discovery D0 may use one
  bounded selector-blind round of independently sourced natural tasks. Its
  schema and fail-closed validators are implemented; no acquisition runs while
  cleaning and coverage thresholds remain unfinished.
- Atomic Full/RD-only and Pair Full/No-Relation are the required RQ2
  comparisons. Qualified blinded Expert and seeded Random selectors are
  available RQ1 baselines on the same support-qualified universe and fixed K.
- Atomic and Pair discoverability bind the same Discovery-population identity.
  Pair admission has no Atomic heredity requirement.
- Assignments are complete-block, replayable, and frozen before generation.
- Assigned-arm task-unit ITT is primary. Fidelity, semantic compliance,
  generation success, and non-target drift are diagnostics, not denominator
  filters.
- Oracle-evaluable secure-code yield remains separate from code validity,
  Oracle evaluability and unknown coverage, functionality, and joint success.
- Every assigned arm ends in exactly one outcome or recorded infrastructure
  failure. Zero, harmful, unknown, invalid, and failed outcomes are retained.
- Only a prospectively authorized formal package may support a scientific
  claim. Smoke, qualification, calibration, and development artifacts cannot.
- Context contrasts and Pair response-pattern labels fail closed until their
  exact prospective rules are frozen; the verified four-cell Pair surface is
  retained without inventing a label.

The detailed implementation map and scientific invariants are in the
[reviewer guide](docs/reviewer-guide.md).

## Active commands

The installed command is `prompt-mechanism-study`. Before formal protocol
activation, the only executable schema-3 study command is a deterministic,
zero-network reviewer smoke; result verification is read-only:

```text
prompt-mechanism-study study smoke REVIEWER_SMOKE_RESULT
prompt-mechanism-study study verify-result REVIEWER_SMOKE_RESULT
```

The smoke traverses all seven stages, writes
`evidence_level=tested`, makes zero provider calls, and can emit only
`NON_CLAIM_TEST_ARTIFACT`.

The human-facing CLI is grouped by research responsibility rather than exposing
every operation at the top level:

```text
study            schema-3 smoke and result verification
data             source normalization and task-unit assembly
curate           blind semantic, contract, and mechanism curation
representation   task-role freezing and Prompt TSG extraction
qualification    Oracle, support, representation, and design gates
artifact         exact-byte bundle verification
```

Run `prompt-mechanism-study GROUP --help` for one stage's actions. Schema-1/2
selector, successor, and factorial runners are not active commands.

Generic exact-byte bundle checking remains available:

```text
prompt-mechanism-study artifact verify BUNDLE
```

## Reproduction

Run the reviewer-facing invariant suite:

```text
.venv\Scripts\python.exe -m pytest -m reviewer -q
```

Run milestone closure and the complete retained suite:

```text
.venv\Scripts\python.exe -m pytest -m milestone -q
.venv\Scripts\python.exe -m pytest -q -o addopts=""
```

Tests and the reviewer smoke establish implementation behavior only. They do
not establish that the formal study ran or that an effect exists.

## Historical boundary

Schema-1/2 execution code is retained in Git history, not as a second live
framework. Immutable historical bundles and the files needed to identify them
remain unchanged and are explicitly outside the default schema-3 reviewer
path. See [legacy artifacts](docs/archive/legacy-artifacts.md) for recovery and
interpretation rules.
