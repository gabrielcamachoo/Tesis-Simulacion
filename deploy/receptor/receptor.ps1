# 01_receptor.ps1 - Detector de anomalias HL7/MLLP EN LINEA (receptor MLLP)
# Tesis G18 WATO. Solo laboratorio aislado (LAB_ONLY.marker + LAB_AUTHORIZED).
# Uso: .\deploy\receptor\receptor.ps1 [-BindHost 127.0.0.1] [-Port 1550]
param(
    [string]$BindHost = "127.0.0.1",
    [int]$Port = 1550
)
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

if (-not (Test-Path (Join-Path $Root "LAB_ONLY.marker"))) {
    Write-Error "Falta LAB_ONLY.marker: lab NO autorizado. Ver README.md (Reglas de seguridad)."
    exit 1
}
if (-not (Test-Path (Join-Path $Root ".venv\Scripts\python.exe"))) {
    Write-Error "Falta .venv. Instalar: python -m venv .venv; .venv\Scripts\pip install -r requirements.txt"
    exit 1
}

$env:LAB_AUTHORIZED = "YES"
$Py = Join-Path $Root ".venv\Scripts\python.exe"

# Settings de despliegue: lab_marker_path -> LAB_ONLY.marker del repo (ver deploy/receptor/make_deploy_settings.py)
$Cfg = Join-Path $Root "evidence_output\settings_deploy.yaml"
& $Py (Join-Path $Root "deploy\receptor\make_deploy_settings.py") $Cfg
if ($LASTEXITCODE -ne 0) { Write-Error "No se pudo generar el settings de despliegue"; exit $LASTEXITCODE }

Write-Output "== Detector en linea: receptor MLLP en ${BindHost}:${Port} (LAB_AUTHORIZED=YES) =="
Write-Output "== Evidencia en evidence_output/ (o --outdir). Ctrl+C para detener. =="
& $Py mllp_receiver.py --config $Cfg --host $BindHost --port $Port --verbose
