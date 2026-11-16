# Frozen research reproduction

`archive/frozen-research-20261007.zip` preserves 359 source, configuration,
fixture and documentation files with their original relative paths and bytes.
Its SHA-256 is
`525d31bab6277e87d6eac3777675360c1cea046122d78e7fc1934c4e2a597393`.
The archive includes the completed study implementation, original reviewer
reader, experiment scripts, R workers and historical tests. Frozen `data` and
`results` remain at their repository locations.

## Isolated Windows environment

Use PowerShell from the repository root and Python 3.12. Choose new extraction,
environment and output directories for each reproduction. The following paths
are examples:

```powershell
$researchRoot = (Get-Location).Path
Get-FileHash -LiteralPath archive/frozen-research-20261007.zip -Algorithm SHA256
Expand-Archive -LiteralPath archive/frozen-research-20261007.zip -DestinationPath .tmp/frozen-research
New-Item -ItemType Junction -Path .tmp/frozen-research/data -Target "$researchRoot/data"
New-Item -ItemType Junction -Path .tmp/frozen-research/results -Target "$researchRoot/results"
uv venv .codex-runtime/frozen-research-venv --python 3.12
uv pip install --python .codex-runtime/frozen-research-venv/Scripts/python.exe -e ".tmp/frozen-research[dev,selectors,jci-study,languages]"
$researchPython = "$researchRoot/.codex-runtime/frozen-research-venv/Scripts/python.exe"
```

The data and result links supply frozen read-only inputs to the commands below.
Every generated package uses a separate `.tmp` destination. Installed imports
resolve to the extracted implementation.

## Completed controlled report

Reassemble its saved scientific outputs with the archived implementation:

```powershell
Push-Location .tmp/frozen-research
& $researchPython -m prompt_mechanism_study.development.jci_ridge report-evaluation --prepared "$researchRoot/data/method/controlled-semantic-20260930/experiment-qualified-inputs" --decisions "$researchRoot/data/method/controlled-semantic-20260930/evaluation-decisions" --evaluation "$researchRoot/results/controlled-semantic-20260930/evaluation" --output "$researchRoot/.tmp/frozen-controlled-report"
Pop-Location
```

The independent verifier checks the measurement implementation against the
original qualification environment. Prepare a separate lookup directory using
the original frozen measurement bytes. The root of the study input directory
must be a physical directory so its repository-relative identity checks resolve
inside that lookup directory. Its child directories and the required curation
metadata can reference the saved inputs:

```powershell
$qualificationRoot = "$researchRoot/.tmp/frozen-measurement-context"
$originalInputs = "$researchRoot/data/method/controlled-semantic-20260930"
$qualifiedInputs = "$qualificationRoot/data/method/controlled-semantic-20260930"
New-Item -ItemType Directory -Path $qualifiedInputs
foreach ($entry in Get-ChildItem -LiteralPath $originalInputs) {
    $destination = Join-Path $qualifiedInputs $entry.Name
    if ($entry.PSIsContainer) {
        New-Item -ItemType Junction -Path $destination -Target $entry.FullName
    } else {
        Copy-Item -LiteralPath $entry.FullName -Destination $destination
    }
}
New-Item -ItemType Junction -Path "$qualificationRoot/data/dataset-curation" -Target "$researchRoot/data/dataset-curation"
New-Item -ItemType Junction -Path "$qualificationRoot/data/method/qwen37flash-qualification-source-review-candidates-v1" -Target "$researchRoot/data/method/qwen37flash-qualification-source-review-candidates-v1"
New-Item -ItemType Directory -Path "$qualificationRoot/src/measurement"
tar -xzf "$originalInputs/frozen-inputs-and-implementation.tar.gz" -C "$qualificationRoot/src/measurement" --strip-components 4 inputs/src/prompt_mechanism_study/measurement/natural_command.py inputs/src/prompt_mechanism_study/measurement/controlled_command.py
Push-Location .tmp/frozen-research
& $researchPython docs/experiments/2026-09-30-jci-result-verifier.py --phase controlled-main --inputs "$qualifiedInputs/experiment-qualified-inputs" --results "$researchRoot/results/controlled-semantic-20260930" --decisions "$researchRoot/data/method/controlled-semantic-20260930/evaluation-decisions" --report "$researchRoot/.tmp/frozen-controlled-report" --output "$researchRoot/.tmp/frozen-controlled-verification"
Pop-Location
```

The original controlled measurement SHA-256 is
`852d131c1b18c276c72d4af16558aaf30c0d22f61d5ab454f91695f44ce4c171`;
the natural worker SHA-256 is
`494fca6ffcec9e126b04d32d915b1e347121d8b4b11f51754712c8468647f808`.
Current exposed-development target-access measurement has its own qualified
implementation and saved observations.

Compare `comparisons.json`, `selector-values.json`, `cases.json`,
`observations.json`, `cost.json`, `natural-cases.json`,
`natural-observations.json` and `natural-status.json` with the saved report in
`results/controlled-semantic-20260930/report`. These files preserve the scientific
outputs. `status.json` additionally identifies the implementation used to
assemble the report.

The complete independent verifier also checks source preparation, assignment,
original observation evidence, all 9,216 evaluation requests, uncertainty,
costs and the unexecuted natural comparison. It makes zero model calls.

## Historical regression checks

```powershell
& $researchPython -m pytest .tmp/frozen-research/tests/test_controlled_semantic.py .tmp/frozen-research/tests/test_controlled_pipeline.py .tmp/frozen-research/tests/test_controlled_repair.py -q --basetemp=.tmp/frozen-research-tests
```

Other historical guides and entry points resolve relative to the extracted
checkout. Their original protocol, measurement rules and evidence identity
continue to govern the corresponding frozen artifacts.

## Verified reproduction

On 2026-10-08, the isolated Python 3.12.13 environments passed 108 current
reviewer tests, three exposed-development checks and 59 archived study tests.
The current smoke reproduced all 40 assignments, retained measurements,
task-unit estimates and table values exactly. The eight frozen scientific files
above were byte-identical. The archived independent verifier checked 7,890
training requests, 9,216 evaluation requests and 6,784 conditional-independence
queries, returning `PASSED_CONTROLLED_MAIN_REPORT`.

These reproductions made zero model calls. The current smoke retains its
`NON_CLAIM_TEST_ARTIFACT` identity; the exposed-development checks retain their
`POST_HOC_EXPOSED_METHOD_CHECK` identity.
