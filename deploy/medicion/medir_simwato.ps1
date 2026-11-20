# medir_simwato.ps1 - CPU/RAM del contenedor del emisor WATO (PC Windows, Docker Desktop).
# Cada muestra escribe una fila CSV con la fase leída de -FaseFile, igual que
# resource_sampler.py en la Pi. Cambiar de fase:  Set-Content $env:TEMP\fase.txt F2
# Ctrl+C para terminar (las filas ya escritas quedan en el CSV).
param(
    [Parameter(Mandatory = $true)][string]$Out,
    [string]$Container = "simwato-wato-benign-1",
    [string]$FaseFile = "$env:TEMP\fase.txt"
)

function ConvertTo-MB([string]$s) {
    # "15.2MiB" / "1.1GiB" / "512KiB" -> MB
    if ($s -match '^([\d\.]+)\s*([KMG]i?B)$') {
        $v = [double]::Parse($Matches[1], [Globalization.CultureInfo]::InvariantCulture)
        switch -regex ($Matches[2]) { '^K' { return $v / 1024 } '^M' { return $v } '^G' { return $v * 1024 } }
    }
    return ""
}

New-Item -ItemType Directory -Force (Split-Path -Parent $Out) | Out-Null
"ts_utc,fase,cpu_pct,mem_mb" | Out-File -FilePath $Out -Encoding utf8
Write-Host "Midiendo $Container -> $Out (fase desde $FaseFile; Ctrl+C para terminar)"
$inv = [Globalization.CultureInfo]::InvariantCulture
while ($true) {
    # docker stats --no-stream tarda ~2 s: esa es la cadencia efectiva.
    $line = docker stats --no-stream --format "{{.CPUPerc}};{{.MemUsage}}" $Container 2>$null
    if (-not $line) { Write-Warning "No se pudo leer $Container"; Start-Sleep 1; continue }
    $cpu, $mem = $line.Split(";")
    $cpu = $cpu.Trim().TrimEnd("%")
    $memMb = ConvertTo-MB ($mem.Split("/")[0].Trim())
    $fase = "sin_fase"
    if (Test-Path $FaseFile) { $t = (Get-Content $FaseFile -Raw).Trim(); if ($t) { $fase = $t } }
    $ts = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss+00:00")
    $memTxt = if ($memMb -ne "") { ([double]$memMb).ToString("0.0", $inv) } else { "" }
    "$ts,$fase,$cpu,$memTxt" | Out-File -FilePath $Out -Append -Encoding utf8
}
