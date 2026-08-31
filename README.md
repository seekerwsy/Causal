# Prompt Mechanism Study

Prompt Mechanism Study is a reviewable research artifact for testing whether a
prospectively frozen prompt intervention changes Oracle-evaluable secure-code
yield while preserving functionality. It is not a deployment or campaign
platform.

The normative design is the
[context-conditioned intervention policy framework](docs/superpowers/specs/2026-08-20-context-conditioned-intervention-policy-framework.md).
The [reviewer guide](docs/reviewer-guide.md) maps that design to the active
entry point, artifacts, implementation, and verification commands.

The normative successor is currently `SPECIFIED_DRAFT`, prospective protocol
`phase-context-policy-v3`. It is not authorized for formal discovery or
confirmation. Existing schema-2.x selector/successor and schema-1.x factorial
commands remain reviewable pre-cutover/legacy boundaries; they do not establish
that the target method was executed.

## One normative method

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
   family-local selectors. Only frozen natural-discovery outcomes may enter;
   confirmation outcomes and arm identities are unavailable.
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

The draft target separates repeatable `QUAL_DEV`, one-shot unexposed
`QUAL_ACCEPT`, formal `DISCOVERY`, held-out `CONFIRMATION`, and `LEGACY_ONLY`
data with task-unit and near-duplicate firewalls. It also uses two correctly
timed freezes: discovery rules are sealed before formal discovery outcomes;
selected slots, the shared confirmation union, assignments, and analysis are
sealed afterward but before confirmation outcomes. Both freeze builders and
their independent verifier are implemented and tested, but no formal freeze
artifact exists because the prospective inputs have not passed qualification.

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

The current outcome-blind candidate-data audit accounts for all 2,165
conservative task units. Its quality-only final dataset contains 1,217 task
units across nine languages; mechanism, Oracle, runtime, and current study
scope do not control this admission. Within that dataset, 164 Python task units
presently satisfy the contract, mechanism, runtime, and local Oracle gates. The
planned 240-task Python population is therefore not yet filled. Separate
inventories retain 102 quality-cleared C/C++ memory-safety
candidates and all 28 BaxBench scenarios, but both replication runtimes remain
unqualified. Exact counts, hashes, Oracle choices, and blockers are in the
[final candidate-data audit](docs/experiments/2026-08-31-final-candidate-data-audit.md).

The pre-cutover successor and schema-1.1 factorial implementations are
specified, implemented, and reviewer-tested under their own contracts. Fresh semantic curation and functional
contracts are complete. Multiple prospectively frozen external Prompt TSG
attempts nevertheless failed Gate C. The latest DevEval run completed all 31
graphs but reached only 27/31 exact matches, with two false-positive present
states and two wrong realizations. All failed bundles are retained and none of
the exposed populations is reused. The active contract-first replacement now
requires one exhaustive task-level decision table spanning every catalog query
for that task family. Two source-only LLM annotations are made independently;
their deterministic consensus compiles the graph locally and maps disagreement
to `unresolved`. The implementation closes under focused replay, but it has not
yet passed a fresh independent extraction qualification. Formal discovery and a new claim-bearing
provider run therefore were not started. The exact stopping boundary is recorded in the
[Gate E readiness audit](docs/gate-e-readiness.md). The tracked schema-1.0 factorial bundles remain
historical formal evidence and are independently replayable; they are not
migrated or reinterpreted as active-protocol results:

- [controlled from-scratch null result](docs/experiments/2026-08-27-factorial-sql-confirm-v3-results.md);
- [bounded scaffold-repair follow-up](docs/experiments/2026-08-27-factorial-sql-scaffold-repair-v1-results.md).

## Entry point and reproduction

The package installs one command: `prompt-mechanism-study`. Until the `3.x`
cutover, its selector/runner subcommands expose reviewable migration and legacy
stage boundaries rather than a claim-bearing execution of the draft target:

```text
prompt-mechanism-study selector-study --help
prompt-mechanism-study interaction-selector --help
prompt-mechanism-study successor-experiment --help
prompt-mechanism-study factorial-experiment --help
```

A pre-cutover factorial run requires a separately verified pre-outcome freeze:

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

The prospective target now has one bounded zero-network execution path and one
read-only result-package boundary:

```text
prompt-mechanism-study target-study smoke REVIEWER_SMOKE_RESULT
prompt-mechanism-study target-study verify-result TARGET_SCHEMA_3_RESULT
```

`smoke` traverses representation, prioritization, hypothesis freeze,
intervention/randomization, measurement, outcome assembly, and
inference/reporting once. It uses deterministic synthetic measurements, makes
zero provider calls, writes `evidence_level=tested`, and can only produce a
`NON_CLAIM_TEST_ARTIFACT`. The same package is then independently reloaded.
It is implementation evidence, not qualification or a formal study run.

`verify-result` requires the exact schema-3.0 package containing the data-role
manifest, accepted budget lineage, both timed freezes, the target randomization
plan, shared model-invariant task-policy bundles, canonical assignments, shared
evidence, fixed-slot yields, report authorization (or explicit null), RQ tables,
and an independently replayed receipt. The verifier reconstructs the complete
four-arm ordering, variant digests, and nullable provider seeds and rejects legacy-shaped
bundles. No tracked formal target package exists yet, so this command does not
authorize or start discovery, provider calls, or confirmation. The index does
not replace the raw responses, measurement records, frozen inputs, execution
environment, command, or provider ledger that its formal references require.

Run the target reviewer invariant suite:

```text
.venv\Scripts\python.exe -m pytest -m reviewer -q
```

Run the complete retained repository suite separately:

```text
.venv\Scripts\python.exe -m pytest -q -o addopts=""
```

The current expected results are 67 reviewer tests, 3 milestone tests, and 185
total tests. The reviewer suite includes the CLI-driven seven-stage smoke,
explicit pre-outcome Atomic/Pair fold freezing, both timed freezes,
assigned-arm ITT, exact on-disk package writing, read-only CLI verification,
independent scientific replay, and report authorization. Test packages write
only to temporary directories, validate implementation only, and are never
reported as study results.

Historical execution code is kept in Git history and historical result bundles,
not as a second live runner. Deployment incidents, provider tuning, calibration
exploration, temporary checkpoints, and unrelated corpora are outside the
default reviewer path.
