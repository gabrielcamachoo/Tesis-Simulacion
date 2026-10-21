$ErrorActionPreference = "Continue"
$env:LAB_AUTHORIZED = "YES"
$root = (Resolve-Path $PSScriptRoot).Path
$py = Join-Path $root ".venv\Scripts\python.exe"
Set-Location $root

if (-not (Test-Path (Join-Path $root "LAB_ONLY.marker"))) {
    Write-Error "Falta LAB_ONLY.marker: lab NO autorizado."
    exit 1
}
if (-not (Test-Path $py)) {
    Write-Error "Falta .venv. Instalar: python -m venv .venv; .venv\Scripts\pip install -r requirements.txt"
    exit 1
}
$log = Join-Path $root "analysis_output\validation\campaign_log.txt"
"INICIO campana $(Get-Date -Format o)" | Out-File -FilePath $log -Encoding utf8

"=== FASE 1: 30 corridas docker, exclude A14 (tag main) ===" | Out-File -Append -FilePath $log -Encoding utf8
& $py run_matrix.py --runs 30 --mode docker --exclude A14 --tag main 2>&1 |
    Out-File -Append -FilePath $log -Encoding utf8
$rc1 = $LASTEXITCODE
"FASE 1 exit=$rc1 $(Get-Date -Format o)" | Out-File -Append -FilePath $log -Encoding utf8

"=== FASE 2: 30 corridas local, solo A14 (tag a14) ===" | Out-File -Append -FilePath $log -Encoding utf8
$a14excl = "A01,A02,A03,A04,A05,A06,A07,A08,A09,A10,A11,A12,A13,A15,A16"
& $py run_matrix.py --runs 30 --mode local --exclude $a14excl --tag a14 2>&1 |
    Out-File -Append -FilePath $log -Encoding utf8
$rc2 = $LASTEXITCODE
"FASE 2 exit=$rc2 $(Get-Date -Format o)" | Out-File -Append -FilePath $log -Encoding utf8

"FIN campana $(Get-Date -Format o) rc1=$rc1 rc2=$rc2" | Out-File -Append -FilePath $log -Encoding utf8
