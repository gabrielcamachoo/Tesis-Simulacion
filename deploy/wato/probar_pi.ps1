# probar_pi.ps1 - Valida y ejecuta flujo WATO remoto (Windows -> Raspberry Pi)
param(
    [string]$PiHost = "192.168.5.134",
    [int]$Port = 1550,
    [int]$Count = 10,
    [double]$Interval = 10.0,
    [ValidateSet("STANDBY", "RUNNING", "ALARM_SIMULATED")]
    [string]$State = "STANDBY",
    [Nullable[int]]$Seed = $null,
    [switch]$ConnectivityOnly
)

$ErrorActionPreference = "Stop"
$Root = Resolve-Path (Join-Path $PSScriptRoot "..\..")
Set-Location $Root

$Py = Join-Path $Root ".venv\Scripts\python.exe"
$Marker = Join-Path $Root "LAB_ONLY.marker"
$Emu = Join-Path $Root "wato_emulator.py"
$WatoScript = Join-Path $Root "deploy\wato\wato.ps1"

if (-not (Test-Path $Py)) { throw "Falta .venv en Windows: $Py" }
if (-not (Test-Path $Marker)) { throw "Falta LAB_ONLY.marker en el repo de Windows." }
if (-not (Test-Path $Emu)) { throw "No existe $Emu" }

$conflicts = Select-String -Path $Emu -Pattern '^(<<<<<<<|=======|>>>>>>>)' -AllMatches
if ($conflicts) {
    throw "wato_emulator.py contiene marcadores de merge. Resolver antes de probar."
}

Write-Output "== Conectividad TCP a la Pi =="
$tnc = Test-NetConnection -ComputerName $PiHost -Port $Port -WarningAction SilentlyContinue
Write-Output ("Host: {0}  Port: {1}  TcpTestSucceeded: {2}" -f $PiHost, $Port, $tnc.TcpTestSucceeded)
if (-not $tnc.TcpTestSucceeded) {
    throw "No hay conectividad TCP hacia ${PiHost}:${Port}."
}

if ($ConnectivityOnly) {
    Write-Output "Modo -ConnectivityOnly: conectividad OK, no se ejecuta emulador."
    exit 0
}

$invokeArgs = @{
    TargetHost = $PiHost
    Port = $Port
    Count = $Count
    Interval = $Interval
    State = $State
}
if ($null -ne $Seed) {
    $invokeArgs["Seed"] = [int]$Seed
}

Write-Output "== Ejecutando emulador WATO contra la Pi =="
Write-Output ("Mensajes: {0}, Intervalo: {1}s, Estado: {2}" -f $Count, $Interval, $State)
& $WatoScript @invokeArgs

Write-Output "== Resumen esperado =="
Write-Output "- En Windows: ACK AA recibidos/validados y contadores finales."
Write-Output "- En Pi: SESSION_START, MSG_RECV, ACK_SENT y SESSION_END en logs/evidencia."
