# 05_suite.ps1 - Suite de pruebas automatizadas del laboratorio
# Uso: .\deploy\validacion\suite.ps1
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { Write-Error "Falta .venv (ver README.md)."; exit 1 }

Write-Output "== pytest tests -q =="
& $Py -m pytest tests -q
exit $LASTEXITCODE
