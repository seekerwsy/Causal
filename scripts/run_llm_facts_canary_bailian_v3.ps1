[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$Root = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$Python = 'D:\MyCode\Causal\.venv\Scripts\python.exe'
# The v2 configuration coordinates remain frozen; the extractor policy hash changes
# automatically with the revised system template and output schema.
$Config = Join-Path $Root 'configs\e2e-pilot\llm-facts-canary-bailian-v2.yaml'
$RunDir = Join-Path $Root 'runs\e2e-pilot\llm-facts-canary-bailian-v3'
$ControlDir = Join-Path $Root 'runs\e2e-pilot\run-controls\llm-facts-canary-bailian-v3-20260814-01'
$EnvFile = Join-Path $Root '.env'

if (-not (Test-Path -LiteralPath $Python -PathType Leaf)) {
    throw 'Fixed Python 3.12 interpreter is unavailable.'
}
if (-not (Test-Path -LiteralPath $EnvFile -PathType Leaf)) {
    throw 'Local .env is unavailable.'
}
if ((Test-Path -LiteralPath $ControlDir) -or (Test-Path -LiteralPath $RunDir)) {
    throw 'The v3 run or control directory already exists.'
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

New-Item -ItemType Directory -Path $ControlDir | Out-Null
$CommandRecord = [ordered]@{
    schema_version = '1.0'
    working_directory = $Root
    python = $Python
    argv = @(
        '-m', 'secaware.cli', 'extract-prompt-tsg',
        '--config', $Config,
        '--run-dir', $RunDir
    )
    credential_source = '.env:ALI_BAILIAN_API_KEY'
    credential_persisted = $false
}
$CommandRecord | ConvertTo-Json -Depth 5 -Compress |
    Set-Content -LiteralPath (Join-Path $ControlDir 'command.json') -Encoding utf8NoBOM
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
    Set-Content -LiteralPath (Join-Path $ControlDir 'environment.json') -Encoding utf8NoBOM

$OldPythonPath = $env:PYTHONPATH
$OldApiKey = $env:ALI_BAILIAN_API_KEY
$env:PYTHONPATH = Join-Path $Root 'src'
$env:ALI_BAILIAN_API_KEY = $ApiKey
$StartedAt = [DateTime]::UtcNow
$ExitCode = 1
try {
    Push-Location $Root
    try {
        & $Python -m secaware.cli extract-prompt-tsg `
            --config $Config `
            --run-dir $RunDir 2>&1 |
            Tee-Object -FilePath (Join-Path $ControlDir 'stdout-stderr.log')
        $ExitCode = $LASTEXITCODE
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

$ResultRecord = [ordered]@{
    schema_version = '1.0'
    started_at_utc = $StartedAt.ToString('o')
    finished_at_utc = [DateTime]::UtcNow.ToString('o')
    exit_code = $ExitCode
    status = if ($ExitCode -eq 0) { 'COMPLETED' } else { 'FAILED' }
}
$ResultRecord | ConvertTo-Json -Depth 5 -Compress |
    Set-Content -LiteralPath (Join-Path $ControlDir 'result.json') -Encoding utf8NoBOM
exit $ExitCode
