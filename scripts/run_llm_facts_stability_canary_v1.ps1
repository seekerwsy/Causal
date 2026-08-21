[CmdletBinding()]
param(
    [ValidatePattern('^llm-facts-stability-canary-v1-20260814-[0-9]{2}$')]
    [string]$RunId = 'llm-facts-stability-canary-v1-20260814-01'
)

$ErrorActionPreference = 'Stop'
$Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$Python = 'D:\MyCode\Causal\.venv\Scripts\python.exe'
$Config = Join-Path $Root 'configs\e2e-pilot\llm-facts-canary-bailian-v2.yaml'
$Prompts = Join-Path $Root 'data\e2e-pilot\llm-facts-canary-v1\prompts.jsonl'
$OutputDir = Join-Path $Root (Join-Path 'runs\e2e-pilot' $RunId)
$EnvFile = Join-Path $Root '.env'

if (Test-Path -LiteralPath $OutputDir) {
    throw "Canary output already exists: $OutputDir"
}
$KeyLines = @(
    Get-Content -LiteralPath $EnvFile |
        Where-Object { $_ -match '^ALI_BAILIAN_API_KEY=' }
)
if ($KeyLines.Count -ne 1) {
    throw 'Expected exactly one ALI_BAILIAN_API_KEY entry.'
}
$ApiKey = $KeyLines[0].Substring('ALI_BAILIAN_API_KEY='.Length)
if ([string]::IsNullOrWhiteSpace($ApiKey)) {
    throw 'ALI_BAILIAN_API_KEY is empty.'
}

New-Item -ItemType Directory -Path $OutputDir | Out-Null
$PromptRecords = @(
    Get-Content -LiteralPath $Prompts |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        ForEach-Object { $_ | ConvertFrom-Json }
)
$CommandRecord = [ordered]@{
    schema_version = '1.0'
    working_directory = $Root
    python = $Python
    script = 'scripts/diagnose_llm_facts_response.py'
    run_id = $RunId
    config = $Config
    prompts = $Prompts
    prompt_ids = @($PromptRecords | ForEach-Object { $_.prompt_id })
    one_response_per_prompt = $true
    credential_source = '.env:ALI_BAILIAN_API_KEY'
    credential_persisted = $false
}
$CommandRecord | ConvertTo-Json -Depth 6 -Compress |
    Set-Content -LiteralPath (Join-Path $OutputDir 'command.json') -Encoding utf8NoBOM
$EnvironmentRecord = [ordered]@{
    schema_version = '1.0'
    captured_at_utc = [DateTime]::UtcNow.ToString('o')
    hostname = [Environment]::MachineName
    os = [Environment]::OSVersion.VersionString
    powershell = $PSVersionTable.PSVersion.ToString()
    python_version = (& $Python --version 2>&1 | Out-String).Trim()
    python_executable = $Python
    working_directory = $Root
}
$EnvironmentRecord | ConvertTo-Json -Depth 5 -Compress |
    Set-Content -LiteralPath (Join-Path $OutputDir 'environment.json') -Encoding utf8NoBOM

$OldPythonPath = $env:PYTHONPATH
$OldApiKey = $env:ALI_BAILIAN_API_KEY
$env:PYTHONPATH = Join-Path $Root 'src'
$env:ALI_BAILIAN_API_KEY = $ApiKey
$StartedAt = [DateTime]::UtcNow
$ExecutionFailures = 0
try {
    Push-Location $Root
    try {
        foreach ($Prompt in $PromptRecords) {
            $PromptDir = Join-Path $OutputDir $Prompt.prompt_id
            try {
                & $Python (Join-Path $Root 'scripts\diagnose_llm_facts_response.py') `
                    --config $Config `
                    --prompts $Prompts `
                    --prompt-id $Prompt.prompt_id `
                    --output-dir $PromptDir 2>&1 |
                    Tee-Object -FilePath (Join-Path $OutputDir ($Prompt.prompt_id + '.log'))
                if ($LASTEXITCODE -ne 0) {
                    $ExecutionFailures += 1
                }
            }
            catch {
                $ExecutionFailures += 1
                $_.Exception.Message |
                    Set-Content -LiteralPath (Join-Path $OutputDir ($Prompt.prompt_id + '.exception.log')) -Encoding utf8NoBOM
            }
        }
    }
    finally {
        Pop-Location
    }
}
finally {
    if ($null -eq $OldPythonPath) {
        Remove-Item Env:PYTHONPATH -ErrorAction SilentlyContinue
    }
    else {
        $env:PYTHONPATH = $OldPythonPath
    }
    if ($null -eq $OldApiKey) {
        Remove-Item Env:ALI_BAILIAN_API_KEY -ErrorAction SilentlyContinue
    }
    else {
        $env:ALI_BAILIAN_API_KEY = $OldApiKey
    }
    $ApiKey = $null
}

$Reports = @(
    Get-ChildItem -LiteralPath $OutputDir -Directory |
        ForEach-Object {
            $ReportPath = Join-Path $_.FullName 'report.json'
            if (Test-Path -LiteralPath $ReportPath -PathType Leaf) {
                Get-Content -LiteralPath $ReportPath -Raw | ConvertFrom-Json
            }
        }
)
$Valid = @($Reports | Where-Object { $_.status -eq 'VALID' }).Count
$Invalid = @($Reports | Where-Object { $_.status -eq 'INVALID' }).Count
$Completed = $Reports.Count
$Summary = [ordered]@{
    schema_version = '1.0'
    status = if ($ExecutionFailures -eq 0 -and $Invalid -eq 0 -and $Completed -eq $PromptRecords.Count) { 'PASS' } else { 'FAIL' }
    started_at_utc = $StartedAt.ToString('o')
    finished_at_utc = [DateTime]::UtcNow.ToString('o')
    counts = [ordered]@{
        total = $PromptRecords.Count
        completed = $Completed
        valid = $Valid
        invalid = $Invalid
        execution_errors = $ExecutionFailures
        pending = $PromptRecords.Count - $Completed - $ExecutionFailures
    }
    records = @($Reports | Sort-Object prompt_id)
}
$Summary | ConvertTo-Json -Depth 8 -Compress |
    Set-Content -LiteralPath (Join-Path $OutputDir 'summary.json') -Encoding utf8NoBOM
$Summary | ConvertTo-Json -Depth 8
if ($Summary.status -ne 'PASS') {
    exit 1
}
