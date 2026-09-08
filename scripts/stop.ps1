$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$statePath = Join-Path $projectRoot ".runtime\traceguard-processes.json"
if (-not (Test-Path -LiteralPath $statePath)) {
    Write-Host "TraceGuard process state was not found; nothing to stop."
    exit 0
}

$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
foreach ($entry in $state.processes) {
    $process = Get-Process -Id ([int]$entry.id) -ErrorAction SilentlyContinue
    if (-not $process) { continue }
    $actualStart = $process.StartTime.ToUniversalTime()
    $expectedStart = [datetime]::Parse([string]$entry.started_at).ToUniversalTime()
    $sameStart = [Math]::Abs(($actualStart - $expectedStart).TotalSeconds) -lt 2
    $samePath = [System.IO.Path]::GetFullPath($process.Path) -eq [System.IO.Path]::GetFullPath([string]$entry.path)
    if (-not ($sameStart -and $samePath)) {
        Write-Warning "Skipped PID $($entry.id): process identity no longer matches the recorded TraceGuard process."
        continue
    }
    Stop-Process -Id $process.Id -Force
    Write-Host "Stopped $($entry.name) (PID $($entry.id))."
}

if ($state.neo4j_started_by_script -eq $true -and (Get-Command docker -ErrorAction SilentlyContinue)) {
    Push-Location -LiteralPath $projectRoot
    try { & docker compose stop neo4j } finally { Pop-Location }
}

Remove-Item -LiteralPath $statePath -Force
Write-Host "TraceGuard stopped."
