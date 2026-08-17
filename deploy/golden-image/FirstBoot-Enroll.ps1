#requires -Version 5.1
<#
.SYNOPSIS
  first-boot auto-enroll for sealed Windows golden-image clones.

.DESCRIPTION
  Invokes the same cycle path as the "AIM Collector Scan" scheduled task
  (enroll once if enroll-token present + no device_token, then heartbeat).
  Use as a RunOnce / Intune proactive remediation when you need enroll
  sooner than the 5-minute task cadence.

  Late secret injection: drop token / enroll-token into
  %ProgramData%\AI-Monitoring\collector\ before calling this script
  (or into FirstBootSecrets under ProgramData\AI-Monitoring\).
#>
[CmdletBinding()]
param(
  [string]$ConfigDir = "$env:ProgramData\AI-Monitoring\collector"
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

function Log($m) { Write-Host "[aim-first-boot] $m" }

$PayloadDir = "$env:ProgramFiles\AIMonitoring\Collector"
$SecretsDrop = "$env:ProgramData\AI-Monitoring\FirstBootSecrets"
$MachineState = Join-Path $ConfigDir 'state'

if (Test-Path $SecretsDrop) {
  New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
  foreach ($name in @('token', 'enroll-token', 'config.json')) {
    $src = Join-Path $SecretsDrop $name
    $dst = Join-Path $ConfigDir $name
    if ((Test-Path $src) -and -not (Test-Path $dst)) {
      Copy-Item -Force $src $dst
      Log "injected $name from FirstBootSecrets"
    }
  }
}

$cycle = Join-Path $PayloadDir 'Invoke-AIMCollectorCycle.ps1'
if (-not (Test-Path $cycle)) {
  # Fall back to install-time location next to helpers.
  $cycle = Join-Path $PSScriptRoot 'Invoke-AIMCollectorCycle.ps1'
}
if (-not (Test-Path $cycle)) {
  # Minimal enroll via python if cycle script missing.
  $Python = Join-Path $PayloadDir 'runtime\python.exe'
  if (-not (Test-Path $Python)) {
    $py = Get-Command py.exe, python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $py) { Log 'no Python / cycle script; exit 0'; exit 0 }
    $Python = $py.Source
  }
  $env:PYTHONPATH = $PayloadDir
  $env:AIM_STATE_DIR = $MachineState
  New-Item -ItemType Directory -Force -Path $MachineState | Out-Null
  $enrollFile = Join-Path $ConfigDir 'enroll-token'
  $cfgPath = Join-Path $ConfigDir 'config.json'
  if ((Test-Path $enrollFile) -and (Test-Path $cfgPath) -and -not (Test-Path (Join-Path $MachineState 'device_token'))) {
    $ingest = (Get-Content $cfgPath -Raw | ConvertFrom-Json).ingest_url
    $tok = (Get-Content $enrollFile -Raw).Trim()
    Log "enrolling against $ingest"
    & $Python -m aim_collector install --ingest-url $ingest --enroll-token $tok 2>&1 | ForEach-Object { Log $_ }
  }
  & $Python -m aim_collector heartbeat 2>&1 | ForEach-Object { Log $_ }
} else {
  Log "running $cycle"
  & $cycle
}

if (Test-Path (Join-Path $MachineState 'device_token')) {
  Remove-Item -Force (Join-Path $ConfigDir 'needs-enroll') -ErrorAction SilentlyContinue
  Set-Content -Path (Join-Path $ConfigDir 'image-state') -Value 'enrolled' -NoNewline
  Log 'device token present — first-boot enroll OK'
} else {
  Log 'no device token yet — scheduled task will retry'
}

exit 0
