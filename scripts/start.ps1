param(
    [int]$ApiPort = 8000,
    [int]$FrontendPort = 5173
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$runtimeDir = Join-Path $projectRoot ".runtime"
$statePath = Join-Path $runtimeDir "traceguard-processes.json"
$python = Join-Path $projectRoot ".venv\Scripts\python.exe"
$vite = Join-Path $projectRoot "frontend\node_modules\vite\bin\vite.js"

if ($ApiPort -ne 8000 -or $FrontendPort -ne 5173) {
    throw "Release ports are fixed: FastAPI 8000 and Frontend 5173."
}
if (-not (Test-Path -LiteralPath (Join-Path $projectRoot ".env"))) {
    throw "Missing .env. Copy .env.example to .env and fill the local Neo4j/LLM values."
}
if (-not (Test-Path -LiteralPath $python)) {
    throw "Missing Python 3.13 .venv. Run scripts/setup_windows.ps1 first."
}
if (-not (Test-Path -LiteralPath $vite)) {
    throw "Missing frontend dependencies. Run scripts/setup_windows.ps1 first."
}
& $python -c "import sys, ssl, fastapi, uvicorn, neo4j, httpx, jsonschema; raise SystemExit(0 if sys.version_info[:2] == (3, 13) and ssl.OPENSSL_VERSION_INFO >= (3, 0) else 1)"
if ($LASTEXITCODE -ne 0) {
    throw "TraceGuard requires Python 3.13 with OpenSSL 3 and installed dependencies."
}

foreach ($port in @($ApiPort, $FrontendPort)) {
    if (Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue) {
        throw "Port $port is already in use. Run scripts/stop.ps1 or stop the owning application."
    }
}

if (-not (Test-Path -LiteralPath $runtimeDir)) {
    New-Item -ItemType Directory -Path $runtimeDir | Out-Null
}

$neo4jStarted = $false
if (-not (Get-NetTCPConnection -State Listen -LocalPort 7687 -ErrorAction SilentlyContinue)) {
    if (Get-Command docker -ErrorAction SilentlyContinue) {
        Push-Location -LiteralPath $projectRoot
        try {
            & docker compose up -d neo4j
            if ($LASTEXITCODE -ne 0) { throw "Docker failed to start Neo4j." }
            $neo4jStarted = $true
        } finally {
            Pop-Location
        }
    } else {
        throw "Neo4j is offline and Docker is unavailable. Start Neo4j on port 7687 first."
    }
}

$env:TRACEGUARD_DATA_DIR = Join-Path $projectRoot "data"
$env:TRACEGUARD_DATABASE_PATH = Join-Path $projectRoot "data\traceguard.db"
$env:TRACEGUARD_RAW_ARCHIVE_DIR = Join-Path $projectRoot "data\raw"
$env:TRACEGUARD_REPORT_DIR = Join-Path $projectRoot "data\reports"
$env:TRACEGUARD_NEO4J_URI = "bolt://127.0.0.1:7687"
$env:LLM_TIMEOUT_SECONDS = "180"
$env:PYTHONUNBUFFERED = "1"

$backend = Start-Process -FilePath $python -ArgumentList @("-m", "uvicorn", "app.main:app", "--app-dir", "backend", "--host", "127.0.0.1", "--port", "$ApiPort") -WorkingDirectory $projectRoot -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtimeDir "backend.stdout.log") -RedirectStandardError (Join-Path $runtimeDir "backend.stderr.log") -PassThru
$node = (Get-Command node -ErrorAction Stop).Source
$frontend = Start-Process -FilePath $node -ArgumentList @($vite, "--host", "127.0.0.1", "--port", "$FrontendPort", "--strictPort") -WorkingDirectory (Join-Path $projectRoot "frontend") -WindowStyle Hidden -RedirectStandardOutput (Join-Path $runtimeDir "frontend.stdout.log") -RedirectStandardError (Join-Path $runtimeDir "frontend.stderr.log") -PassThru

$state = @{
    api_port = $ApiPort
    frontend_port = $FrontendPort
    neo4j_started_by_script = $neo4jStarted
    processes = @(
        @{ name = "backend"; id = $backend.Id; path = $backend.Path; started_at = $backend.StartTime.ToUniversalTime().ToString("o") },
        @{ name = "frontend"; id = $frontend.Id; path = $frontend.Path; started_at = $frontend.StartTime.ToUniversalTime().ToString("o") }
    )
}
$state | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $statePath -Encoding UTF8

function Wait-HttpOk {
    param([string]$Url, [int]$Seconds = 45)
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 3
            if ($response.StatusCode -eq 200) { return $true }
        } catch {}
        Start-Sleep -Milliseconds 750
    }
    return $false
}

if (-not (Wait-HttpOk -Url "http://127.0.0.1:$ApiPort/api/system/health")) {
    throw "FastAPI did not become healthy. See .runtime/backend.stderr.log."
}
$health = Invoke-RestMethod -Uri "http://127.0.0.1:$ApiPort/api/system/health" -TimeoutSec 5
if ($health.data.graph.connected -ne $true) {
    throw "FastAPI is running, but Neo4j is not connected. Run scripts/check.ps1 for details."
}
if (-not (Wait-HttpOk -Url "http://127.0.0.1:$FrontendPort")) {
    throw "Frontend did not become healthy. See .runtime/frontend.stderr.log."
}

Write-Host "TraceGuard started"
Write-Host "Frontend: http://127.0.0.1:$FrontendPort"
Write-Host "FastAPI:  http://127.0.0.1:$ApiPort"
Write-Host "Run scripts/check.ps1 for the full release health check."
