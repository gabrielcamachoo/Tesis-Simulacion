# 02_wato.ps1 - Emulador del monitor WATO EX-35 (trafico benigno STANDBY)
# Tesis G18 WATO. Envia ORU^R01 sinteticos por MLLP con ACK validado.
# Uso: .\deploy\wato\wato.ps1 [-TargetHost 127.0.0.1] [-Port 1550] [-Count 10] [-Interval 6.0] [-State STANDBY] [-Seed 2026101401]
param(
    [string]$TargetHost = "127.0.0.1",
    [int]$Port = 1550,
    [int]$Count = 10,
    [double]$Interval = 6.0,
    [string]$State = "STANDBY",
    [int]$Seed = 0
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

$env:LAB_AUTHORIZED = "YES"
# Nota: el intervalo se formatea con cultura invariante (evita "6,5" en locale es)
$IntervalS = $Interval.ToString([System.Globalization.CultureInfo]::InvariantCulture)
$EmuArgs = @("wato_emulator.py", "--host", $TargetHost, "--port", "$Port",
             "--state", $State, "--count", "$Count", "--interval", $IntervalS,
             "--ack-timeout", "5")
if ($Seed -ne 0) { $EmuArgs += @("--seed", "$Seed") }

Write-Output "== WATO emulator: $Count msg cada $IntervalS s -> ${TargetHost}:${Port} ($State) =="
& $Py @EmuArgs
