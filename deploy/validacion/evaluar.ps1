# 06_evaluar.ps1 - Evalua una corrida existente (TP/FP/TN/FN, recall, precision, latencia)
# Uso: .\deploy\validacion\evaluar.ps1 -RunDir runs\20261017_110410
param([Parameter(Mandatory = $true)][string]$RunDir)
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { Write-Error "Falta .venv (ver README.md)."; exit 1 }
if (-not (Test-Path $RunDir)) { Write-Error "No existe la corrida: $RunDir"; exit 1 }

& $Py -c "from evaluate import run_from_dir; print(run_from_dir(r'$RunDir'))"
exit $LASTEXITCODE
