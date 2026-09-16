# Framework simplification verification — 2026-09-08

Scope: the five approved simplifications of the existing seven-stage research
path. This is an implementation and reproduction record, not study evidence.
The protocol remains `SPECIFIED_DRAFT`; no provider call or formal study was run.

## Changes

| Step | Concrete result |
|---|---|
| Retire competing design path | Removed `qualification study-design`, `freeze_study_design`, its sole-use sampling/Gaussian-power helpers and six obsolete tests. The actual-procedure power design remains the sole active method. History remains in Git. |
| Separate smoke inputs from procedure | Moved fixed synthetic inputs and offline raw responses into packaged `fixtures/reviewer_smoke.json`, with a small typed loader. `target_workflow.py` runs the actual generation parser, syntax check, local TLS Oracle, blinded functional-response validator and outcome assembly. It no longer constructs measured labels directly. |
| Remove verifier re-entry | Saved-package verification checks budget, preflight, freezes, evidence and tables once each. Standalone public verifiers still validate prerequisites. Independent effect/power calculations remain separate from production estimators. |
| Separate historical tests | Moved 18 development-policy, prompt-version, transport and archive-identity tests from `reviewer` to `extended`. Active scientific boundaries and current representation behavior remain in the reviewer gate. |
| Narrow inactive interfaces | Removed future modifier specifications, active-plan branches and classified-label states. Existing empty serialized fields remain readable, with explicit blocked statuses; active or partial rules are rejected. No schema/version was added. |

The ten core reading files decreased from 12,576 to 11,208 lines (10.9%). Total
source Python decreased from 36,723 to 35,455 lines, including the new 91-line
fixture loader. These are counts against the working-tree baseline immediately
before this simplification, not against Git HEAD. Fixed JSON fixture data is
counted separately; moving it out of Python does not eliminate those inputs.

## Validation

- Focused workflow, inference and study-design tests: **40 passed**.
- Default reviewer collection: **127** cases; complete retained collection: **236**.
- Full retained suite: **236 passed in 232.85 seconds**, with no failures or skips;
  this includes all 127 reviewer cases.
- The end-to-end regression observes all 80 actual measurements, checks secure
  and insecure code against the fixture's explicit TLS behavior, and checks the
  blinded functional request and response. A profiler asserts one visit to each
  major saved-package verification boundary.
- Old frozen smoke: independently verified, unchanged bundle SHA-256
  `5fdea23d5a041dd3888f0afe8b88c14c9c01fbca506c8baf3177cb7cf1af3c9c`.
- New smoke: 7 stages, 20 synthetic task units, 80 assignments, 80 measurements,
  80 outcomes, zero provider calls; `tested`, `NON_CLAIM_TEST_ARTIFACT`, claims false.
- Two new smoke executions match **all 20 files byte for byte**, with bundle
  SHA-256 `eacb108fef259cb1a6082d3ceeae615ee731780a7708b1c0c7f6bf18e71ca5d7`.
- Old/new inference plans and complete family estimates are exactly equal.
  All 80 outcomes match by policy/task/arm/seed, and every non-identity RQ-table
  field is unchanged. Package identity changes reflect actual prompt-content
  binding and its downstream hashes; old artifacts were not rewritten.
- Built and installed the wheel in a new isolated environment. Smoke and saved
  result verification work outside the source directory with no third-party
  runtime packages. Both validation environments pass dependency checks.

## Reproduction identities and commands

Environment: Windows 11 build 26200, Python 3.12.13. The test environment is
`.tmp/research-repair-clean-env`, with pytest 9.1.1 and the unchanged external
versions in [the repair requirements](2026-09-07-repair-requirements.txt).
The fresh installed-package environment is `.tmp/simplification-installed-env`.

Source identity is SHA-256 of the compact, key-sorted JSON map of relative paths
to SHA-256 for `src/**/*.py`, `src/**/*.json`, `tests/**/*.py`,
`configs/formal/*.json` and `pyproject.toml`:
`5a6e7f08dd16d52ee596b860b2be01cf0930c5842d4aaef87bdaaacf0bae2eef`.
The exact file map is `.tmp/simplification-environment.json`.
Final wheel SHA-256 is
`e65aca24b14fd18833d62aae209b39e8b771e78cc9c31ea1455d4e62a24eca7f`.

Executed from repository root unless noted:

```powershell
.tmp/research-repair-clean-env/Scripts/python.exe -m pytest tests/test_target_workflow.py tests/test_target_inference.py tests/test_study_design.py -q -o addopts='' -p no:cacheprovider --basetemp=.tmp/simplification-test03
.tmp/research-repair-clean-env/Scripts/python.exe -m pytest -q -o addopts='' -p no:cacheprovider --basetemp=.tmp/simplification-test04
.tmp/research-repair-clean-env/Scripts/python.exe -m pip wheel . --no-deps --no-build-isolation --no-index --wheel-dir .tmp/simplification-final-wheel
.tmp/research-repair-clean-env/Scripts/python.exe -m venv .tmp/simplification-installed-env
.tmp/simplification-installed-env/Scripts/python.exe -m pip install --no-index --no-deps --force-reinstall .tmp/simplification-final-wheel/prompt_mechanism_study-1.6.0-py3-none-any.whl
# From D:/MyCode/Causal/.tmp, using the installed command:
.\simplification-installed-env\Scripts\prompt-mechanism-study.exe study smoke D:/MyCode/Causal/.tmp/simplification-reproduction-smoke
.\simplification-installed-env\Scripts\prompt-mechanism-study.exe study verify-result D:/MyCode/Causal/.tmp/simplification-reference-smoke
.\simplification-installed-env\Scripts\prompt-mechanism-study.exe study verify-result D:/MyCode/Causal/.tmp/research-repair-reference-smoke
```

Use new output directories when repeating these commands. The first new smoke is
at `.tmp/simplification-reference-smoke`; its independent reproduction is at
`.tmp/simplification-reproduction-smoke`. The fixed smoke qualification inputs,
representation facts and FCI/relation evidence do not execute or qualify their
producers. Functional verdicts are offline responses, not measured evaluator
accuracy. Formal qualification, population allocation, scientific power and
provider-budget closure remain prerequisites for a future full scientific run.

## Follow-up: four architecture boundaries

After the five-step pass above, the author approved the four further changes
identified in the architecture review. The earlier measurements and artifacts
above retain their original meaning.

| Boundary | Final implementation |
|---|---|
| Source-data tools | `curate` now exposes `prepare`, `review`, `repair`, and `finalize`. All 23 maintained operations preserve their exact arguments, defaults and function bindings. The archived single-provider content-review command is removed. Historical command aliases are not kept. Existing data preparation and repair logic remains available where required to reconstruct the frozen data. |
| Module ownership | `discovery_population.py` owns outcome-blind source preparation, role allocation and D0; `prioritization.py` owns candidate support, Atomic selection, fixed slots and unique dispatch. `study_planning.py` owns qualification, power and budget; `study_design.py` owns actual assignment preflight and the two freezes. Active imports use these owners directly. No schema or competing execution path was added. |
| Writing results | The writer reuses one evidence verification for table assembly and prewrite component checks. It retains a second, independent full replay from the saved bytes. Evidence verification therefore occurs twice during writing, previously three times. Standalone public verifiers still perform full verification. |
| Ranking numerics | `selector_numerics.py` provides one ridge-logit gradient solver and sigmoid. Atomic retains its design standardization, prediction arithmetic and 300-iteration limit; Pair retains covariate-only scaling, interaction columns and 800 iterations. Confirmatory inference and the independent verifier do not use this solver. |

The former 3,350-line prioritization module now has 1,933 lines, with 1,396 lines
assigned to population preparation. The former 2,614-line study-design module
now has 859 lines, with 1,768 lines assigned to pre-study planning. Total source
Python is 35,547 lines versus 35,455 before this follow-up: this pass separates
responsibilities and eliminates repeated work; it does not claim a net source
line reduction. Shared string validation resides in the existing record layer.

Validation:

- Selector/population focused suite: **24 passed**.
- Workflow/inference/selector/curation focused suite: **68 passed**.
- Full retained suite: **238 passed in 219.93 seconds**, no failures or skips,
  including all **129** default reviewer cases.
- Two added numerical regressions preserve pre-refactor Atomic probabilities
  and Pair coefficients/scaling. A direct comparison with the pre-change
  implementations also matched their floating-point outputs exactly.
- All 23 curation command parsers match their previous argument contracts and
  handler bindings. The curation dispatch regression now exercises the actual
  grouped CLI. The smoke regression requires exactly two evidence checks when
  writing and one visit to each boundary when independently reading a package.
- A newly installed wheel, used outside the source directory, verifies the
  canonical v5 source bundle through `curate finalize task-units verify`, returning
  `VERIFIED_DATA_FOUNDATION_COMPLETE_PROMPT_TSG_DEFERRED`.
- Its new smoke matches the previous `.tmp/simplification-reference-smoke`
  **in all 20 files byte for byte**. The bundle SHA-256 remains
  `eacb108fef259cb1a6082d3ceeae615ee731780a7708b1c0c7f6bf18e71ca5d7`.
  The previous package also passes standalone verification after the refactor.
- Both environments pass dependency checks. Wheel Python/JSON contents match
  source exactly; source identity, edited-document links and whitespace checks pass.

The test environment and external requirements are unchanged. The fresh wheel
environment is `.tmp/architecture-installed-env`. The source identity uses the
same path-map procedure above and is
`9e639675435e704025086ef8e492b20ba39a471ada61bb03f5292e56b531b7ec`;
the exact map is `.tmp/architecture-environment.json`. The wheel SHA-256 is
`4a96857c71b763cebfb1b2a6b58df76090f81c12539c2cb5caec579c791b261f`.

```powershell
.tmp/research-repair-clean-env/Scripts/python.exe -m pytest -q -o addopts='' -p no:cacheprovider --basetemp=.tmp/architecture-test04
.tmp/research-repair-clean-env/Scripts/python.exe -m pip wheel . --no-deps --no-build-isolation --no-index --wheel-dir .tmp/architecture-wheel
.tmp/research-repair-clean-env/Scripts/python.exe -m venv .tmp/architecture-installed-env
.tmp/architecture-installed-env/Scripts/python.exe -m pip install --no-index --no-deps .tmp/architecture-wheel/prompt_mechanism_study-1.6.0-py3-none-any.whl
# From D:/MyCode/Causal/.tmp:
.\architecture-installed-env\Scripts\prompt-mechanism-study.exe study smoke D:/MyCode/Causal/.tmp/architecture-reference-smoke
.\architecture-installed-env\Scripts\prompt-mechanism-study.exe study verify-result D:/MyCode/Causal/.tmp/simplification-reference-smoke
.\architecture-installed-env\Scripts\prompt-mechanism-study.exe curate finalize task-units verify D:/MyCode/Causal/data/dataset-curation/reviewer-task-unit-dataset-v5
```

All executed study output remains `tested`, non-claim, with zero provider calls.
Formal qualification and study execution remain unopened.
