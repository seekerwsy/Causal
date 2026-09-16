# Paper-scale experiment preparation

Date: 2026-09-11. Status: source preparation complete; server workspace
consolidated; revised functional-judge four-case exposed pilot executed and passed.
Protocol remains `SPECIFIED_DRAFT`.

## Current successor after open-TSG development

The v2 population and pilot below describe their original preparation time.
The [later bounded development](2026-09-11-open-tsg-effects.md) exposed another
30 task units, all recorded before task-level method feedback. The current
`research-candidate-pool-v3` therefore retains 1,962 independent tasks (692 Python),
155 protected inputs, 47 pending source defects and one dependent source variant.
There are 779 complete, 1,182 partial and one unresolved specification. Existing
source reviews project to 148 supported task-policy combinations on 67 tasks;
no new semantic success or formal admission was granted. Both earlier pools remain intact.

The current qualification manifest SHA-256 is
`fbcb29f4df0b783faad69015fb922d4998f6629a27d6bddb1d851ca40e2e9820`;
v3 output manifest SHA-256 is
`b23366fea4101ed007ad2966ef492b64a50ddef0f4e917b8257e8e54396ade0e`.
Run the same preparation command below with the current qualification manifest
to reproduce v3 into a new directory. To reproduce v2, use its saved
`qualification-input.json` snapshot instead of the now-updated repository file.

## Available population at the v2 preparation freeze

The planning objective is to use the full available independent population for
the paper's main experiments, subject to prospectively defined scope and
candidate-specific applicability. Development, qualification, Discovery and
Confirmation must remain separate. No D/C ratio, final sample size or formal
role is assigned by this preparation.

The original pool contained 1,995 tasks. Three were subsequently inspected to
develop the functional-review rule; their exposures were already recorded in
`configs/formal/qualification_data_manifest.json`. The preparation entry now
requires that manifest, checks its source identity, and protects each exposed
task's entire near-duplicate group before choosing pool representatives.

The resulting `data/dataset-curation/research-candidate-pool-v2` contains **1,992**
independent tasks. It preserves 125 protected inputs, 47 source defects pending
correction and one dependent variant: all 2,165 prepared task IDs are accounted
for. No new source labels or outcomes were used, and v1 is unchanged.

| Language | Independent pool tasks |
|---|---:|
| Python | 722 |
| C | 274 |
| C++ | 243 |
| JavaScript | 211 |
| C# | 169 |
| Rust | 122 |
| PHP | 119 |
| Java | 116 |
| Go | 16 |

The pool retains 788 complete, 1,203 partial and one unresolved functional
specification. These are source descriptions; all syntax-valid generated code
enters the revised functional review. Existing three-axis source support remains
218 Atomic task-policy combinations on 97 tasks. These combinations are not
qualified interventions, and the existing book establishes no supported Pair.
Nine-language syntax handling alone does not qualify nine-language representation,
interventions or security Oracles; those remain scientific coverage work.

## Reproduce the population

Input prepared-source manifest SHA-256:
`2015d760cbeaacff16e701ad25a507e5973960a31b0ecd7de8d4b769bf7a741c`.
Qualification input file SHA-256:
`6b6da40edbc038c8bf0ee771f648caf91eae8aca98798869a114184f67890c1d`.
The output includes a JSON snapshot of that qualification input.
Output manifest SHA-256:
`0fc7e53e68ff3dac4fe53d674561139a7e2d3ae73d82bf9eca47907bd9d46776`.

```powershell
$env:PYTHONPATH = (Resolve-Path src).Path
$studyPython = '.tmp/sequential-source-review-20260909/final-reviewer-env/Scripts/python.exe'
& $studyPython -m prompt_mechanism_study.cli curate prepare candidate-pool data/dataset-curation/research-source-use-v2 NEW_OUTPUT --qualification-manifest configs/formal/qualification_data_manifest.json
& $studyPython -m pytest tests/test_datasets.py -k prepared_pool -q -p no:cacheprovider --basetemp=NEW_TEST_OUTPUT
```

The focused invariant test passed in Python 3.12.13. It independently derives
membership, checks group-wide exposure exclusion including an unselected sibling,
rejects a mismatched source identity, preserves exact task records and incomplete
specifications, and verifies candidate projection without altering design labels.
The new bundle's exact bytes also passed verification. This change does not
affect randomization, inference or the existing seven-stage smoke outputs; those
checks are reused rather than rerun.

## Immediate measurement check

Run the existing four-case exposed development pilot with the revised prompt:
`fjcalv4-validation-gtf-fail-a`, `fjcalv4-validation-pdf-fail-a`,
`fjcalv4-validation-slurm-pass-a`, `fjcalv4-validation-sqlite-pass-a`.
Keep their existing reference labels and the existing gate: at least 3/4 correct,
at most one false pass, no invalid response. Do not tune this candidate after
viewing its pilot responses or open the independent QUAL_ACCEPT reservation.
This is a bounded regression check on known Python cases; it cannot establish
unknown-case accuracy, language-wide accuracy or independent qualification.

Use `functional_judge.preflight` and `functional_judge.run_phase(..., 'pilot', ...)`
with `configs/functional-judge/functional-oracle-qwen37flash.json`. Local preflight
at `.tmp/functional-task-relative-pilot-preflight` verified the fixed snapshot,
prompt, evaluator, cases and calibration specification. Input identities are in
its `report.json`. The revised prompt SHA-256 is
`f750e2fe095e1a40a5d8dc9b6ee959231e99e38082e2b0f64d4a7085dc3adbb4`.

The existing CNY 100 preexperiment authorization applies. Before this run the
recorded conservative remaining budget was CNY 97.773134; four calls reserved CNY 0.009832 under
the previously approved per-call ceiling, not a fresh price quote. Each selected
request plus system prompt is under 4,400 UTF-8 bytes. Use no fallback model or
provider retry. Record actual attempts, failed responses and conservative costs
in the existing execution ledger after the run.

Execution uses the existing remote Python 3.12.11 image. Credentials remain remote. The
server initially closed the SSH connection. After the owner reported restoration,
the connection succeeded and the existing image ID and prior project deployment
hashes matched their recorded identities. The owner subsequently approved the
specific upload and requested that server files be consolidated in wsy's work
directory. The active locations are now:

- `/home/wsy/work/prompt-mechanism-study/inputs`: verified pilot inputs;
- `/home/wsy/work/prompt-mechanism-study/results`: current output location;
- `/home/wsy/work/prompt-mechanism-study/archive`: verified historical inputs/results;
- `/home/wsy/work/prompt-mechanism-study/.env`: the owner-only active credential.

The credential was copied and compared on the server without exporting its value.
The root project instructions now require this workspace layout for future runs.

The four old home-level deployment, experiment, transfer and upload directories
have been removed after archiving and verifying 86,318 non-cache files. The
owner-only archive is `archive/history-through-20260911.tar.gz` (516,069,301 bytes),
SHA-256 `dac129c6163aa3444164108b4e65d7aa4bcf3add783d1a89408c2494a85e2f4d`.
The archive index records each original path and file hash. Cleanup removed 3,111
regenerable cache files; total regular-file storage decreased by approximately
1.54 GB after including the archive/index. The server's `archive/cleanup-summary.json`
records the result. Other projects were not changed. Historical credential files
remain in the owner-only archive, so it is private server history, not a reviewer
distribution artifact.

The prepared 13-file local archive is
`.tmp/functional-task-relative-pilot-20260911-payload.tar.gz`, SHA-256
`e5a16fc127e40467a6a63734f8ccb5c0daa1f66d3eb149e320cf1ac54e44198a`.
It contains four required Python module files, the fixed evaluator/gate/prompt,
the existing exposed calibration data, the author decision, a thin execution
snippet and an input-hash manifest. It contains no credential file. The execution
snippet checks hashes and an empty output directory before remote preflight and
the existing four-case pilot; it does not introduce another measurement path.

The explicitly approved SCP upload succeeded. The archive hash and all extracted
input hashes matched on the server. Automatic approval review then rejected the
API-execution command, stating that authorization for the server upload and
four-case evaluation did not explicitly name the external DashScope API destination.
A separate question asked for approval to send the four exposed tasks, their
candidate code and judge instructions to `dashscope.aliyuncs.com`, within the
existing budget and a CNY 0.01 cap. No project implementation files or credential
values would be included in the API request. The owner explicitly approved that
API request before execution. No alternate route around a rejected action was used.

## Executed pilot result

The fixed `qwen3.7-flash-2026-07-15` candidate completed exactly four provider
attempts, without retries, and passed the unchanged gate: **4/4 correct**, zero
false pass, false fail, unknown or invalid response.

| Development case | Reference | Judge | Relevant finding |
|---|---|---|---|
| GTF append | fail | fail | Write mode overwrites instead of appending. |
| SQLite metadata | pass | pass | The requested table and index metadata are returned. |
| PDF bag of words | fail | fail | The result is printed instead of saved to the requested file. |
| Slurm exit code | pass | pass | The requested job state is logged and its exit code returned. |

Raw requests, responses, environment and input hashes are preserved under
`data/functional-judge/task-relative-development-pilot-v1` and in the server's
current `results` directory. Pilot summary bundle SHA-256:
`2543dbb5cfc494cd1bebd042eb41db2a39d1a2d9b2fe560c06a825e834f1acfb`.
Execution-input/environment bundle SHA-256:
`54f8a3e3be715cc4ac1a0d398281d67e87cf5df88294b1c58a0175e444a8b222`.
Independent replay checked bundle bytes, the four predeclared case IDs and
request hashes, exact candidate-code lines, raw response hashes, reference labels,
evidence-line bounds and all summary counts. It agreed with the saved report.

The existing cost ledger records four actual calls at the conservative approved
ceiling, CNY **0.009832** for this run. Cumulative conservative spend is CNY
2.236698 and minimum remaining budget is CNY **97.763302**. These are upper-bound
accounting figures, not an assertion of the provider's exact bill; this adapter
does not retain token-usage billing metadata. No QUAL_ACCEPT call or formal
experiment was made. The remaining 12 regression cases were not run under this
four-case authorization.

This result supports continuing development of the revised judge. Four known
Python examples, with pass/fail references only, do not establish accuracy on
genuinely unknown cases, the full nine-language population or independent
qualification. The formal-use flags and qualification thresholds remain unchanged.

After this bounded check, resolve representation/intervention/measurement coverage
and measure candidate-specific support before choosing and freezing the all-data
study's role allocation, power plan and formal budget. Passing the pilot alone
does not authorize the full experiment.
