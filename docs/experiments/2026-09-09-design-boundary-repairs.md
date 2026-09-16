# D0 role lineage and actual-support power repair

Date: 2026-09-09. Protocol: `phase-context-policy-v3`, still `SPECIFIED_DRAFT`.

Both repairs are implemented and tested. The executions below are local,
non-claim reproductions. No natural-data acquisition, new qualification acceptance,
formal Discovery, provider Confirmation or external model call was performed.

## Final behavior

### D0 preserves qualification while extending Discovery

The supplementation receipt carries the original `DataRoleManifest`; the normal
study package carries its successor. Production and independent verification
require every old binding to remain exact, including Discovery itself, and permit
only new Discovery bindings. Added task identities must match the receipt and
remain independent of every old role. Source family and exposure provenance must
agree with the frozen coverage scope and accepted dispositions.

Qualification, its acceptance plan and its power/budget memo keep the original
manifest identity. Discovery freezes the successor only after the additive
relationship passes. Changing a protected role, rewriting old provenance, adding
a near-duplicate, expanding the source scope or omitting the original manifest
blocks the path. No second acceptance run or general manifest-migration framework
was added.

### Power uses actual task membership before Confirmation

`TargetPowerSimulationPlan.task_support` records coordinate, task unit, source
stratum and realization index. It supports partial and higher-order overlap and
different realization assignments for a shared task. Shared simulated components
follow task identity, while the existing task-unit estimator and family bootstrap
remain unchanged.

Pre-Discovery qualification freezes the assumptions, scenario grid, family ceiling,
sample/stratum counts, weights, margins, alpha, target power, seeds and budget.
The existing Confirmation preflight specializes only family membership and actual
task/realization support, reruns the frozen scenarios and stores the complete
`actual_power_results`. The independent verifier reconstructs the table from
assignments and separately reconstructs categorical draws and family inference.
Inadequate power blocks execution and exposes the failed results on the preflight
error. Empty families produce no artificial power result.

Task and stratum counts remain fixed per effect within a track. This repair does
not support changing those counts after materialization failure, replacing slots,
reducing target power, retuning assumptions from Discovery effects or topping up
the original task pool. Simulation remains conditional on its declared assumptions;
the implementation does not establish that the actual research population has
adequate power.

Previously frozen non-claim packages retain their exact identities and original
shared/disjoint checks. The record layer allows only explicitly declared absent
extensions, omits them from canonical hashes, and rejects explicit null encodings
of those extensions. Every newly generated preflight stores actual-support power;
both production and independent reporting reject formal claims without it.

## Reading map

| Concern | Production | Independent verification / saved field |
| --- | --- | --- |
| D0 membership and qualification origin | `discovery_population.validate_discovery_role_transition`; `study_design.freeze_target_discovery_design` | `verification.design._verify_discovery_population`; original manifest inside the existing receipt, successor in `data_role_manifest.json` |
| Task-bound power simulation | `study_planning.bind_target_power_to_assignments`; `simulate_target_power` | `verification.qualification.verify_target_power_simulation`; `FormalBudgetPreflight.actual_power_results` |
| Frozen assumptions and final power Gate | `study_design.validate_formal_budget_preflight` | `verification.qualification._check_formal_budget_preflight`; preflight identity inside `ConfirmationFreeze` |
| Historical identity and claim boundary | `records.canonical_value`; `selector_analysis.authorize_target_report` | strict decoding in `verification.integrity`; claim checks in `verification.reporting` and `verification.verifier` |

The seven stages, one active entry point and ten-file reviewer reading order are
unchanged. The normative clauses are in [the protocol](../protocol.md), §§4, 9.1,
19 and 25.2; the practical path is in [the reviewer guide](../reviewer-guide.md).

## Validation

The complete retained suite passed in a fresh Python 3.12.13 environment:
**243 passed, zero failures, errors or skips**, in 188.84 seconds. A final fixture
extension then exercised both repairs together through package saving and loading;
all **5 focused tests passed** in 35.01 seconds. Production source did not change
after the complete run. The fixture extension changed only the two design-test
files.

Coverage includes three partially overlapping effects, task-identity rather than
row-rank coupling, different realizations for shared tasks, preservation of every
non-evaluable simulation replicate, a failed-power preflight with retained results,
assumption/support tampering, exact additive D0 membership, protected-role/source
scope violations, and a full D0-plus-partial-overlap package independently reread.

The dependency-free wheel was installed in a second fresh environment and invoked
outside the source checkout. Its Python/JSON package members exactly matched the
current source. The seven-stage smoke generated 80 assignments, measurements and
outcomes over 20 task units, with zero provider calls. Its new bundle SHA-256 is:

```text
3c63bb76176af0f344b40cab8e388917005a9d7895e7e57d29e9afcb7a8e073e
```

The earlier reference package independently verified with its unchanged SHA-256:

```text
eacb108fef259cb1a6082d3ceeae615ee731780a7708b1c0c7f6bf18e71ca5d7
```

Fourteen of its twenty files are byte-identical to the new reproduction, including
assignments, assembled outcomes, effect estimates and RQ tables. The six changed
files are the preflight and its dependent Confirmation/index/verification/manifest
records. The original package was not overwritten. The frozen v5 source/contract
bundle also passed installed-CLI verification; its manifest remains
`33ab47c3b7f40f9a66a008460510e50c8a9afbda08ec951aab1d400e6cda93da`.

The environment is Windows 11 build 26200, Python 3.12.13, pytest 9.1.1 and the pinned
`causal-learn` 0.1.4.7 backend. Dependencies were installed offline from the existing
local package cache. Both environment dependency checks passed.

## Exact local reproduction record

From the repository root, the completed validation commands were:

```powershell
.tmp/design-repairs-clean-env/Scripts/python.exe -m pip install --no-index --find-links .tmp/design-repairs-wheelhouse -r .tmp/design-repairs-requirements.txt
.tmp/design-repairs-clean-env/Scripts/python.exe -m pip install --no-index --no-deps --no-build-isolation -e .
.tmp/design-repairs-clean-env/Scripts/python.exe -m pytest -q -o addopts= -o cache_dir=.tmp/design-repairs-pytest-cache --basetemp=.tmp/design-repairs-test07 --junitxml=.tmp/design-repairs-test07.xml
.tmp/design-repairs-clean-env/Scripts/python.exe -m pytest tests/test_discovery_population.py tests/test_study_design.py -k 'd0 or two_freeze' -q -o cache_dir=.tmp/design-repairs-pytest-cache --basetemp=.tmp/design-repairs-test08 --junitxml=.tmp/design-repairs-test08.xml
.tmp/design-repairs-clean-env/Scripts/python.exe -m pip wheel --no-index --no-deps --no-build-isolation --wheel-dir .tmp/design-repairs-wheel .
.tmp/design-repairs-installed-env/Scripts/python.exe -m pip install --no-index --no-deps .tmp/design-repairs-wheel/prompt_mechanism_study-1.6.0-py3-none-any.whl
```

Installed commands were run with working directory `D:/MyCode/Causal/.tmp`:

```powershell
D:/MyCode/Causal/.tmp/design-repairs-installed-env/Scripts/prompt-mechanism-study.exe study smoke D:/MyCode/Causal/.tmp/design-repairs-reference-smoke
D:/MyCode/Causal/.tmp/design-repairs-installed-env/Scripts/prompt-mechanism-study.exe study verify-result D:/MyCode/Causal/.tmp/architecture-reference-smoke
D:/MyCode/Causal/.tmp/design-repairs-installed-env/Scripts/prompt-mechanism-study.exe curate finalize task-units verify D:/MyCode/Causal/data/dataset-curation/reviewer-task-unit-dataset-v5
```

Use a new empty output location when repeating the smoke. Temporary environments,
package cache, JUnit records and output directories are development verification
material, not additional reviewer-package content. The public reviewer commands
remain the ones in the README.

The exact source/test/config identity map and environment details are recorded in
`.tmp/design-repairs-environment.json`. The final map SHA-256 is
`5c106cbece1d72c4d4f87b50b2d1fb269084ed384bbc1a39161784accf23c92a`;
the built wheel SHA-256 is
`967a017504e779bdff36463b198fff1db789478050137ecf94a8a6543e5a3bf5`.
The worktree contains pre-existing edits, so its recorded Git HEAD is not presented
as the complete identity of this repair. No frozen research input was changed.
