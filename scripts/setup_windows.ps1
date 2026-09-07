param(
    [string]$IndexUrl = "https://pypi.tuna.tsinghua.edu.cn/simple"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot ".."))
Set-Location -LiteralPath $projectRoot

# Codex/部分实验环境会注入禁用 PyPI 的变量，并继承未启动的本地代理。
# 这里只修改当前脚本及其子进程，不持久修改用户或系统配置。
Remove-Item Env:PIP_NO_INDEX -ErrorAction SilentlyContinue
$env:NO_PROXY = "*"
$env:no_proxy = "*"

$indexHost = ([System.Uri]$IndexUrl).Host
Write-Host "Installing TraceGuard Python dependencies from $IndexUrl"
python -m pip install -e ".[dev]" --no-build-isolation --index-url $IndexUrl --trusted-host $indexHost

python -c "import fastapi, uvicorn, pytest; print('Ready: FastAPI', fastapi.__version__, '| Uvicorn', uvicorn.__version__, '| pytest', pytest.__version__)"

