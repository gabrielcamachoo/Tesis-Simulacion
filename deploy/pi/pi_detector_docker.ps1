# 04_pi_detector_docker.ps1 - Despliegue de la TOPOLOGIA Raspberry Pi (docker)
# Simula en docker la topologia de despliegue de la Pi (red interna 172.30.0.0/24,
# IPs fijas, mismo codigo). Ver docs/RASPBERRY_PI_SETUP.md sec 6.3 y
# docs/SIMULACION_RANSOMWARE.md sec 4. H2 (latencia) solo se verifica en la Pi fisica.
# Requiere Docker Desktop corriendo.
# Uso: .\deploy\pi\pi_detector_docker.ps1 [-Seed 20261014] [-Exclude "A14"]
param(
    [int]$Seed = 20261014,
    [string]$Exclude = "A14"
)
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

if (-not (Test-Path (Join-Path $Root "LAB_ONLY.marker"))) {
    Write-Error "Falta LAB_ONLY.marker: lab NO autorizado."
    exit 1
}
$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { Write-Error "Falta .venv (ver README.md)."; exit 1 }

docker info 2>$null | Out-Null
if (-not $?) {
    Write-Error "Docker no esta corriendo. Abrir Docker Desktop y reintentar."
    exit 1
}

$env:LAB_AUTHORIZED = "YES"
Write-Output "== Topologia Pi (docker): red interna 172.30.0.0/24, receptor 172.30.0.20 =="
Write-Output "== Campana A01-A16 (exclude: $Exclude), semilla $Seed =="
& $Py run_experiment.py --mode docker --exclude $Exclude --seed $Seed
exit $LASTEXITCODE
