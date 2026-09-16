# Minimal scientific test suite

The maintained suite has **110 representative cases in 90 test functions**.
`python -m pytest -q` runs all of them. There is no hidden extended suite or
reviewer marker filter. This is the minimum maintained coverage for the current
seven-stage method, not exhaustive coverage of every supported implementation.

## Run only what changed

Use Python 3.12 with the repository's `dev,selectors,languages` extras installed.
For a local TSG change, select the relevant test or file, for example:

```text
python -m pytest -q tests/test_source_inventory_extraction.py -k independent_participant
```

For changes across scientific stages or a reviewer handoff, run once:

```text
python -m pytest -q
```

The suite already includes a seven-stage offline smoke and independent saved-result
verification. To inspect a standalone smoke package, use:

```text
prompt-mechanism-study study smoke NEW_OUTPUT_DIRECTORY
prompt-mechanism-study study verify-result NEW_OUTPUT_DIRECTORY
```

`python -m pytest -q -m milestone` selects only the smoke. It is not an additional
gate after the complete suite passes. Reuse verification for unchanged components.

## What the remaining checks protect

| Boundary | Necessary error detection |
| --- | --- |
| Input identity and source preparation | Changed system/task input, outcome-informed selection, incorrect task-unit merging, exposed evaluation tasks, and changed role/fold assignments |
| TSG representation | Merged atomic requirements or distinct objects, wrong operation/subject roles, lost conditions, unsupported evidence, and unknown states incorrectly treated as absence |
| TSG review and repair | Incomplete review, unsupported extra assertions, lost failed tasks, retrofitted references, and repair messages/schema order changed before delivery |
| Candidate construction and prioritization | Scope-changing edits, unsupported candidates, Atomic heredity imposed on Pair, changed Full/Ablation comparisons, incorrect selector numerics, and duplicated model-effect dispatch |
| Hypothesis freeze and randomization | Changed assumptions or task support, inadequate power, repeated qualification, post-outcome freezes, and assignment/variant/seed drift |
| Measurement and outcome assembly | Security/functionality conflation, lost judge failures, unknowns counted as secure, and forged raw measurement bindings |
| Inference and reporting | Wrong ITT denominators or realization weights, seed-level task inflation, incorrect bootstrap/multiplicity or estimates, unfrozen labels, and claims from non-claim fixtures |
| Reviewer reproduction | Broken seven-stage execution, empty-support failures, altered bundle bytes, and results that fail independent replay |

Each retained parameter distinguishes a decision state or failure boundary.
The TLS check uses representative secure/insecure/unknown examples; it is not a
complete API matrix or an empirical accuracy qualification. The actual independent
verifier remains separate from production estimators. Its calculations are not
replaced with mocks or cached expectations.

Removed material includes old extraction paths, historical snapshots, full-source
rebuilds, UI checks, broad language/provider combinations, redundant parameters,
and helpers used only by deleted tests. Frozen experimental inputs, results,
protocol thresholds and production behavior are unchanged.

New tests require a concrete scientific error that these checks cannot detect.
Prefer updating the representative case for that boundary. Do not grow a second
suite or use test totals as research progress. Actual model checks remain separately
scoped experiments; passing these offline tests does not establish TSG quality.

## Verification, 2026-09-15

The suite shrank from 461 cases to 110, and test code from 15,412 to 6,701 lines.
All 110 cases passed in 38.54 seconds in the previously verified isolated Python
3.12.13 environment, with zero provider calls. The seven-stage smoke's saved
manifest is byte-identical to the preceding complete-suite result. Exact command
and local report:

```text
.tmp/tsg-workflow-review-env/Scripts/python.exe -X utf8 -m pytest -q --basetemp=.tmp/minimum-core-01 --junitxml=.tmp/minimum-core-01.xml --durations=5
```
