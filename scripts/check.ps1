param(
    [string]$ApiUrl = "http://127.0.0.1:8000",
    [string]$FrontendUrl = "http://127.0.0.1:5173"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $python)) {
    throw "Missing .venv. Run scripts/setup_windows.ps1 with Python 3.13 first."
}

# Windows local storage paths intentionally override Docker-only /data paths.
$env:TRACEGUARD_DATA_DIR = Join-Path $projectRoot "data"
$env:TRACEGUARD_DATABASE_PATH = Join-Path $projectRoot "data\traceguard.db"
$env:TRACEGUARD_RAW_ARCHIVE_DIR = Join-Path $projectRoot "data\raw"
$env:TRACEGUARD_REPORT_DIR = Join-Path $projectRoot "data\reports"
$env:TRACEGUARD_NEO4J_URI = "bolt://127.0.0.1:7687"
if (-not $env:TRACEGUARD_DEFAULT_TIMEZONE) {
    $env:TRACEGUARD_DEFAULT_TIMEZONE = "UTC+08:00"
}
if (-not $env:LLM_TIMEOUT_SECONDS) {
    $env:LLM_TIMEOUT_SECONDS = "45"
}

& $python (Join-Path $PSScriptRoot "check_environment.py") --api-url $ApiUrl --frontend-url $FrontendUrl
exit $LASTEXITCODE
