# Prompt Mechanism Study

Prompt Mechanism Study is the research prototype for **CausalGuide: Causal Analysis
for Explainable Security Guidance in LLM Code Generation**. It connects task-bound
security requirements to explicit prompt-policy comparisons and independently measured
effects, then specifies how that evidence supports scoped explanations and guidance.
Oracle-evaluable secure-code yield is the primary safety endpoint; functionality is
measured separately. Budgeted prioritization and randomized confirmation support this
evidence-to-guidance objective. It is not a deployment platform.

The normative method is the stable [active protocol](docs/protocol.md).
Its active protocol is `phase-context-policy-v3`, currently
`SPECIFIED_DRAFT`: the method core is implemented and tested, but no formal
discovery, provider confirmation, or claim-bearing schema-3 result exists.

The [local manuscript](paper/fse2027/main.tex) uses three reader-facing stages:
Structured Graph Representation, Requirement-Level Causal Analysis, and
Evidence-Grounded Explanations and Guidance. The seven scientific operations below
remain the only active path. The explanation content/withholding contract is now
specified in protocol Section 15.1; its human-facing implementation, exact adoption
criteria, and RQ4 material/analysis design still require prospective completion.
The paper-facing name does not rename protocol IDs, code, or frozen artifacts.

Source screening now asks whether a task supports the declared security comparison;
exact interventions and controls are validated during protocolization. Oracle
qualification may cover only the profiles and code forms in the research scope.
The [bounded development check](docs/experiments/2026-09-10-proportional-prototype.md)
records this revision. Frozen five-axis source reviews retain their original meaning.
The subsequent [rapid inclusion pass](docs/experiments/2026-09-10-rapid-dataset-inclusion.md)
materialized 1,995 independent research-pool tasks. The current
[main-study preparation](docs/experiments/2026-09-11-main-study-preparation.md)
and [natural-source preflight](docs/experiments/2026-09-16-tsg-natural-source-preflight.md)
preserve 41 subsequently exposed task units for development and carry **1,954**
independent tasks forward in `data/dataset-curation/research-candidate-pool-v4`.
Incomplete functional specifications remain included. Existing source evidence now
supports 144 task-policy combinations on 65 unexposed tasks; this is preparation
capacity, not formal experimental admission. Earlier pool snapshots remain frozen.

Syntax-valid code now enters the blinded LLM functional review regardless of source
completeness. The judge assesses the original task, allows reasonable implementation
freedom, and retains unknown for genuinely unassessable material requirements.
The revised prompt is prospective and awaits qualification; frozen results retain
their original interpretation.

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
- Open TSG concepts are developed from exposed source prompts, then fixed before
  Discovery. Task-local operation instances and requirement-object bindings are preserved;
  external CWE/task-family labels do not set the extraction scope.
- Optional D0 occurs once after representation qualification and before Discovery freeze.
  Trigger, allocation and stopping use only frozen context task-unit counts, sources
  and budgets. Feature states, Pair cells and selector evidence cannot enter its inputs.
  Unknown memberships and remaining context gaps are retained; candidate support and
  power are checked separately. No acquisition has been executed.
- Atomic Full/RD-only and Pair Full/No-Relation are the required RQ2
  comparisons. Qualified blinded Expert and seeded Random selectors are
  available RQ1 baselines using the same frozen discoverability/fold decisions
  and fixed K.
- Atomic and Pair discoverability bind the same Discovery-population identity.
  Pair admission has no Atomic heredity requirement.
- Assignments are complete-block, replayable, and frozen before generation.
- Assigned-arm task-unit ITT is primary. Fidelity, semantic compliance,
  generation success, and non-target drift are diagnostics, not denominator
  filters.
- Each task-policy receives one frozen realization. Estimates average within
  each realization and then apply its original weight; failed allocations are
  recorded without replacement.
- Before Confirmation outcomes, power is rechecked on the actual task-effect
  and realization table, including partial overlap, using the assumptions and
  thresholds frozen before Discovery. A failed check blocks execution.
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

The active Prompt TSG extractor builds one source-only instance graph per task.
`task_input.prepare_task_input` binds the actual system message, user request and
declared language; later generation must use that corresponding input. Exact
recognized Python-template facts are compiled once; custom messages need source
annotation. A model extracts source records with requirement composition and participants,
conditions and scope; the program compiles their declared references into edges.
Negation, thresholds, exact subjects,
conditions and distinct operation instances must survive construction.

Graph construction ends before candidate-specific scope assessment. The bounded
[current development workflow](docs/tsg-workflow-stability.md) uses one comprehensive
source review and at most one local semantic patch to affected records. The scope assessor accepts explicit
type or measurement-domain evidence and preserves unknowns otherwise. This removes
abstract type guesses from object categories without changing source facts.
The current representation path preserves atoms and finite and/or/not/opaque
composition with attached participants, conditions, modality and target scope. One source review may
request one local patch; the program then compiles graph bindings. There is no
separate free binding call. Input assumptions cannot become editable requirements.
The program retains deterministic readings of actual targets, conditions and
composition for debugging; correct prose cannot fill missing structural fields.
The decoder shares binding semantics with compilation. Adding these readings to
the existing paid review showed no detection gain in a frozen ten-call comparison,
so that prompt addition was removed. The [binding-check pilot](docs/experiments/2026-09-16-tsg-binding-checks.md)
improved its known controls, but the [cross-task detection comparison](docs/experiments/2026-09-16-tsg-binding-coverage-transfer.md)
still missed a deleted failure condition. Detailed review detected3/4 corrupted cases
versus2/4 for ordinary review; one proposed equivalent control had uncertain parent
scope semantics. The detailed component did not meet its declared adoption gate and
is retained only in the experiment archive. The default remains one ordinary source
review; repair preserves source impacts that review already accepted.
Normal calls fall from four to three, with at most five including repairs. The
[workflow guide](docs/tsg-workflow-stability.md) defines this single active path;
the [development report](docs/experiments/2026-09-16-tsg-atomic-records.md) records
its bounded validation and limitations. The default110-case suite passes, without
adding tests. Four bounded development batches are closed: completed graphs were
0/3, 2/3, 1/1 and 0/1; complete semantic acceptance was zero in every batch. These
different versions are not pooled as an accuracy estimate. The final diagnostic
correction passed45 focused checks and retained-response inspection, without a new
provider run. Only three already exposed tasks were used; protected data is untouched.

The subsequent [composition/locality revision](docs/experiments/2026-09-16-tsg-candidate-locality.md)
preserves requirement composition and local source impacts, distinguishes execution
guards from independent contexts, and scores candidate dependencies separately.
The unchanged110-case suite passes. One book pilot compiled in three calls at
CNY0.824160 but retained missing guards and widened requirement scope; model review
made no correction. Reference alignment defects are recorded separately. This pilot
stopped without expansion. Natural extraction reliability remains unresolved.

Historical results keep their original interpretation. The closed-vocabulary
[18/18 stability series](docs/experiments/2026-09-16-qwen-max-stability.md) did not
validate open source facts. Natural-source checks exposed unsupported participation,
lost branches and wrong scope. The preceding
[source-premise attempts](docs/experiments/2026-09-16-tsg-source-premise-repair.md)
accepted0/3 and0/2 complete outputs. No current stability, transfer accuracy or
independent qualification is established. Historical
[Qwen](docs/experiments/2026-09-16-qwen-max-recheck.md) and
[DeepSeek](docs/experiments/2026-09-16-deepseek-tsg.md) results remain separate.

The downstream assessor separates applicability from source expression, preserves
unknowns and cannot change source facts or relations. Missing edges never establish
independence; an unexpressed requirement never establishes insecure generated code.
Provider failures and incomplete graphs remain in the recorded task population.

The [candidate-construction path](docs/tsg-candidate-construction.md) selects and
normalizes asserted atomic requirements from exposed development graphs. Correct
composites remain non-actionable; candidate selection cannot split them or
assign different meanings to the same source node. Reviewed factors enter the
existing vocabulary freeze and Atomic/Pair policy records. Fresh graphs supply
state-blind scope binding and the existing qualification/support producer.
Independent qualification, natural candidate support and formal Discovery remain
unfinished. Synthetic smoke fixtures do not establish those empirical properties.

Evaluation checks both required source meanings and every extra graph assertion,
including typed roles, conditions, completeness and downstream state premises.
Source-cited local impacts restrict unknown propagation; unlocalized/shared effects
remain blocking. Independent non-gating contexts are distinct from execution guards.
Candidate-level source checks and assertion review now accompany full-graph diagnostics.
Representation development is currently bounded to previously exposed tasks;
all old runs retain their frozen sources, code and original judgments. Current
quality, costs and the single next action are maintained in the workflow guide.
Historical attempts are available in the linked experiment records rather than
being repeated as competing current instructions here.

## Active commands

The installed command is `prompt-mechanism-study`. Before formal protocol
activation, use the deterministic zero-network reviewer smoke and read-only verification:


```text
prompt-mechanism-study study smoke REVIEWER_SMOKE_RESULT
prompt-mechanism-study study verify-result REVIEWER_SMOKE_RESULT
prompt-mechanism-study study verify-development SAVED_DEVELOPMENT_RUN
```

Explicitly authorized bounded development uses `study development OUTPUT
--development-plan FROZEN_PLAN`; it cannot assign formal roles or permit claims.
The completed comparison's exact offline reproduction is in its report above.

The smoke traverses all seven stages, writes
`evidence_level=tested`, makes zero provider calls, and can emit only
`NON_CLAIM_TEST_ARTIFACT`.
Its fixed synthetic inputs and offline raw responses are packaged separately;
code parsing, local security measurement and blinded functional-response validation
use the actual measurement path.

The human-facing CLI is grouped by research responsibility rather than exposing
every operation at the top level:

```text
study            reviewer smoke, bounded development and independent verification
data             source normalization and task-unit assembly
curate           blind semantic, contract, and mechanism curation
representation   task-role freezing and Prompt TSG extraction
qualification    Oracle, support, representation, and design gates
artifact         exact-byte bundle verification
```

Run `prompt-mechanism-study GROUP --help` for one stage's actions. Schema-1/2
selector, successor, and factorial runners are not active commands.
Data preparation is grouped under `curate prepare`, `curate review`,
`curate repair` and `curate finalize`. Study reproduction consumes the released
frozen source bundle; it does not require rerunning historical data repairs.

Generic exact-byte bundle checking remains available:

```text
prompt-mechanism-study artifact verify BUNDLE
```

## Reproduction

Run the reviewer-facing invariant suite for changes across scientific stages or
a reviewer handoff. It includes the seven-stage smoke and independent result
verification. For daily development, use the affected checks described in the
[test guide](tests/README.md); local TSG edits do not require the whole suite.

```text
python -m pip install -e ".[dev,selectors,languages]"
.venv\Scripts\python.exe -m pytest -q
```

The maintained suite contains 110 representative cases, all run by the command
above. There is no separate extended suite. To select only the offline smoke:

```text
.venv\Scripts\python.exe -m pytest -m milestone -q
```

Tests and the reviewer smoke establish implementation behavior only. They do
not establish that the formal study ran or that an effect exists.

The immutable content-cleaned reviewer baseline is
`data/dataset-curation/reviewer-task-unit-dataset-v5`. It contains exactly ten
files and independently verifies under manifest SHA-256
`33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`.
The active data-preparation population includes all 2,165 tasks across nine
languages and all original quality dispositions. Its derived package is
`data/dataset-curation/research-source-use-v2`; `prepared-tasks.json` holds the
actual source inputs and prompt-bound functional contracts, and `task-uses.json`
records roles, source recovery and pending candidate requirements. The release
includes 404 independently re-reviewed current contracts, context screening for
1,459 tasks, and native-asset reviews for 284 tasks. This grants no formal eligibility.
The 66 exposed tasks and 56 qualification reservations
retain their original inputs and restrictions. See the
[dataset contract](docs/research-dataset-spec.md) for verification and counts.

## Historical boundary

Schema-1/2 execution code is retained in Git history, not as a second live
framework. Immutable historical bundles and the files needed to identify them
remain unchanged and are explicitly outside the default schema-3 reviewer
path. See [legacy artifacts](docs/archive/legacy-artifacts.md) for recovery and
interpretation rules.
