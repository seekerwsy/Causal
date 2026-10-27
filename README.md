# CausalGuide

The normative [Atomic protocol](docs/protocol.md) is `phase-context-policy-v3`,
**SPECIFIED_DRAFT**. The active implementation supports source preparation,
offline component reproduction, independently verified results and explicitly
authorized bounded development. Formal execution remains inactive.

Each Atomic policy changes one complete prompt requirement while preserving
non-target behavior. Prompt TSG records source meaning and scope. The primary
analysis uses assigned-arm, deduplicated-task-unit ITT. Generation failures,
unknown measurements and post-assignment diagnostics retain their assigned
denominators. Secure-code yield, code validity, Oracle evaluability,
functionality and joint success are reported separately.

## Reproduce the reviewer artifact

Use Python 3.12 from the repository root:

```text
python -m pip install -e ".[dev,selectors,languages]"
python -m pytest -q
prompt-mechanism-study study smoke NEW_OUTPUT_DIRECTORY
prompt-mechanism-study study verify-result NEW_OUTPUT_DIRECTORY
```

The smoke runs real FCI on synthetic observations and measures bundled offline
code/review responses. It makes zero provider calls and saves a
`NON_CLAIM_TEST_ARTIFACT`. The independent verifier replays assignment,
measurement, statistical estimates and table rows from the saved package.

The [reviewer guide](docs/reviewer-guide.md) identifies stage inputs and outputs,
scientific invariants, six result files and ten core reading files. The
[test guide](tests/README.md) identifies the default suite and the separate
exposed-development checks.

## Seven scientific stages

| Stage | Responsibility |
| --- | --- |
| Representation | Preserve source requirements, objects, conditions and scopes; construct Atomic candidates. |
| Prioritization | Use shared candidates and folds for Full and RD-only; retain every fixed selector slot. |
| Hypothesis freeze | Fix policies, populations, models, budgets and analysis before evaluation. |
| Intervention/randomization | Bind one requirement to Target, No-op, Style and Generic-security prompts and replay task/arm/seed assignment. |
| Measurement | Independently measure security, validity and functionality from generated code. |
| Outcome assembly | Account for every assignment, including terminal, unknown and failed outcomes. |
| Inference/reporting | Estimate task-unit ITT effects and independently reconstruct reported rows. |

Context-modifier inference remains blocked pending prospective assignment and
joint inference rules. Pair interaction remains outside the Atomic method.
Natural-task transfer, automatic representation accuracy and a graph selection
advantage require their own prospectively specified evidence.

## Implementation and commands

`src/cli.py` is the single command entry; `src/target_workflow.py` coordinates
the seven stages. Scientific logic belongs to `data`, `tsg`, `discovery`,
`experiment`, `measurement` and `verification`. `artifact_io.py` supplies shared
serialization and integrity checks. `verification` retains independent
assignment and numerical calculations.

Fixed slots directly determine unique selected candidates. The dispatch manifest
binds their protocolization results to the fixed-slot ledger. Inference computes
all endpoints over the same task hierarchy. Result-table assembly is pure;
the workflow writes the package and independently verifies its readback.

Source contracts are authoritative; graphs are compiled from them. Candidate
assessments remain separately bound to their source contracts. Record decoding
uses cattrs with exact primitive types and canonical readback checks. Response
structure uses JSON Schema; source evidence and scientific constraints retain
their explicit checks.

| Operation | Command |
| --- | --- |
| Prepare source data | `data --help` |
| Extract and assess source representations | `representation --help` |
| Submit complete prepared prompts | `representation submit-preparation INPUTS SUBMISSION OUTPUT` |
| Submit complete Atomic reviews | `representation submit-review INPUTS SUBMISSION OUTPUT` |
| Compute exposed safety-gain decisions | `prioritization safe-decisions INPUTS ANALYSIS OUTPUT --minimum-gain THRESHOLD` |
| Run authorized bounded development | `study development OUTPUT --development-plan FROZEN_PLAN` |
| Verify its results | `study verify-development SAVED_RUN` |
| Verify exposed observer and decision records | `study verify-repair INPUTS OBSERVATIONS DECISIONS OUTPUT` |
| Run endpoint qualification | `qualification --help` |

The current [exposed-development check](docs/experiments/2026-10-07-controlled-repair.md)
uses real native-tool target-access observations, signed edit gains with baseline
abstention, and complete preparation/review submissions. Its saved 168 probes
and 400 decisions retain their development evidence identity. Offline decision
reproduction and its independent verifier additionally require `.[analysis]`.

The [JCI sharing development study](docs/experiments/2026-10-14-jci-sharing-results.md)
executes multi-environment structure searches and policy consumers, with a separate
exposed historical-code analysis. Its [frozen design](docs/experiments/2026-10-14-jci-sharing-plan.md)
and saved results distinguish the original comparison, causal-query diagnostics,
and shared-component calibration. Use `study jci-sharing`,
`study diagnose-jci-sharing`, and `study verify-jci-sharing`; these commands require
`.[analysis]` and the declared R/pcalg environment. The evidence remains bounded
method development.

The [joint-context JCI study](docs/experiments/2026-10-14-jci-joint-policy-results.md)
tests directional ancestry information and zero-effect constrained refitting on
96 computational repetitions and the exposed historical outcomes. Use the same
study and verification entry points with `--joint-policies`; add
`--zero-effect-refit` for the constrained consumer. Its report separates known
graphical information from finite-sample policy value and direct-CI comparisons.

The [exposed direction comparison](docs/experiments/2026-10-14-jci-direction-comparison-results.md)
uses eight frozen training/CAL splits of the exposed historical tasks, equal-budget
policy consumers, a direct-CI comparison and an ancestry-versus-adjacency ablation.
Its [design](docs/experiments/2026-10-14-jci-direction-comparison-plan.md) uses
`study jci-sharing --joint-policies --historical-only` with `direction-plan.json`;
the existing joint verification command reconstructs all task-level comparisons.
The results retain their post-hoc development identity.

The [JCI reliability study](docs/experiments/2026-10-14-jci-reliability-results.md)
replays false non-ancestry decisions and tests conservative structure search,
finite regularization, direct-dependence protection and separated calibration
roles under its [frozen SCM design](docs/experiments/2026-10-14-jci-reliability-plan.md).
Use `study jci-reliability`, `study verify-jci-reliability` and
`study diagnose-jci-reliability`. Its prospective comparisons cover all registered
mechanisms and direct/structural comparators with a common multiplicity family.
The evidence remains a bounded computational method check.

The [limited-budget replay](docs/experiments/2026-10-14-jci-budget-replay-results.md)
freezes 24 scoped expression-policy candidates, request budgets, confirmation
panels and independent test tasks. Its [design](docs/experiments/2026-10-14-jci-budget-replay-plan.md)
uses the same historical joint-study command with `budget-plan.json`.
Discovery learners receive only budgeted real random-mixture outcomes; the saved
results separately report requirement ancestry, candidate changes and test value.

## Frozen research

Completed controlled studies retain their original inputs, observations, rules
and reports. Their implementation, scripts and historical tests are preserved in
[the verified source archive](archive/frozen-research-20261007.zip). Follow the
[archive reproduction guide](docs/archive-reproduction.md) to run them in an
isolated environment with the matching frozen implementation.

The [controlled study report](docs/experiments/2026-09-30-controlled-semantic-results.md)
records 9,216 evaluation requests, eleven executed primary comparisons and an
unexecuted natural comparison whose frozen eligible sets are empty. Its primary
nonconstant intervals include zero; the frozen JCI, FCI and RD actions coincide.
The [experiment documents](docs/experiments/README.md) identify the retained
designs and results. These historical artifacts keep their original evidential
limits. The [paper draft](paper/fse2027/main.tex) is a separate research artifact.
