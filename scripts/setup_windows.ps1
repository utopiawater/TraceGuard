param(
    [string]$IndexUrl = "https://pypi.tuna.tsinghua.edu.cn/simple"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
$venvPath = Join-Path $projectRoot ".venv"
$venvPython = Join-Path $venvPath "Scripts\python.exe"
Set-Location -LiteralPath $projectRoot

function Test-Python313 {
    param([string]$Command, [string[]]$Prefix = @())
    try {
        $args = @($Prefix) + @("-c", "import sys; raise SystemExit(0 if sys.version_info[:2] == (3, 13) else 1)")
        & $Command @args
        return $LASTEXITCODE -eq 0
    } catch {
        return $false
    }
}

$pythonCommand = $null
$pythonPrefix = @()
if ((Get-Command py -ErrorAction SilentlyContinue) -and (Test-Python313 -Command "py" -Prefix @("-3.13"))) {
    $pythonCommand = "py"
    $pythonPrefix = @("-3.13")
} elseif ((Get-Command python -ErrorAction SilentlyContinue) -and (Test-Python313 -Command "python")) {
    $pythonCommand = "python"
}
if (-not $pythonCommand) {
    throw "Python 3.13 is required. Install Python 3.13 (64-bit) and rerun this script."
}

if (-not (Test-Path -LiteralPath $venvPython)) {
    Write-Host "Creating Python 3.13 virtual environment at .venv"
    $venvArgs = @($pythonPrefix) + @("-m", "venv", $venvPath)
    & $pythonCommand @venvArgs
}
if (-not (Test-Python313 -Command $venvPython)) {
    throw ".venv is not Python 3.13. Remove or rename it, then rerun setup_windows.ps1."
}

# Only child processes receive these network overrides; system settings are unchanged.
Remove-Item Env:PIP_NO_INDEX -ErrorAction SilentlyContinue
$env:NO_PROXY = "*"
$env:no_proxy = "*"
$indexHost = ([System.Uri]$IndexUrl).Host

Write-Host "Installing TraceGuard dependencies with Python 3.13"
& $venvPython -m pip install --upgrade pip setuptools wheel --index-url $IndexUrl --trusted-host $indexHost
& $venvPython -m pip install -e ".[dev]" --no-build-isolation --index-url $IndexUrl --trusted-host $indexHost

$nodeVersion = (& node -p "process.versions.node")
if ($LASTEXITCODE -ne 0 -or [int]($nodeVersion.Split('.')[0]) -lt 20) {
    throw "Node.js 20 or newer is required."
}
& npm.cmd ci --prefix frontend

& $venvPython -c "import ssl, fastapi, uvicorn; print('Ready: Python 3.13 | OpenSSL', ssl.OPENSSL_VERSION, '| FastAPI', fastapi.__version__, '| Uvicorn', uvicorn.__version__)"
Write-Host "Setup complete. Copy .env.example to .env, fill local secrets, then run scripts/start.ps1."
