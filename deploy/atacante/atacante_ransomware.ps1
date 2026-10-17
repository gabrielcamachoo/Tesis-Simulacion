# 03_atacante_ransomware.ps1 - Campana del ATACANTE (simulacion de ransomware)
# Tesis G18 WATO. Comportamientos modelados (SIN malware real):
#   A01 suplantacion de origen | A05/A06 corrupcion del stream MLLP
#   A13 reconexiones repetidas  | A14 silencio periodico (hostage del canal)
#   A16 cambio de identidad a mitad de sesion
# Requiere receptor corriendo (01_receptor.ps1) o usa run_experiment (orquestador completo).
# Uso: .\deploy\atacante\atacante_ransomware.ps1 [-Seed 2026101401]
param([int]$Seed = 2026101401)
$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

if (-not (Test-Path (Join-Path $Root "LAB_ONLY.marker"))) {
    Write-Error "Falta LAB_ONLY.marker: lab NO autorizado."
    exit 1
}
$Py = Join-Path $Root ".venv\Scripts\python.exe"
if (-not (Test-Path $Py)) { Write-Error "Falta .venv (ver README.md)."; exit 1 }

$env:LAB_AUTHORIZED = "YES"
$Exclude = "A02,A03,A04,A07,A08,A09,A10,A11,A12,A15"
Write-Output "== Campana ransomware: A01,A05,A06,A13,A14,A16 (20 inyecciones, ~201 s) =="
Write-Output "== Orquestador completo: benigno -> ataque -> benigno -> evaluacion =="
& $Py run_experiment.py --mode local --exclude $Exclude --seed $Seed
exit $LASTEXITCODE
