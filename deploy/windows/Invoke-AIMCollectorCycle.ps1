#requires -Version 5.1
<#
.SYNOPSIS
  Periodic collector cycle for Windows: per-user scan+flush, then
  machine-level enroll/heartbeat so the fleet coverage dashboard can tell
  healthy devices from dead ones.

  Installed to Program Files and invoked by the "AIM Collector Scan"
  scheduled task (SYSTEM, every 5 minutes).

.NOTES
  - Per-user spools live under %USERPROFILE%\.aim-collector (hooks write there).
  - Machine enrollment identity lives under
    %ProgramData%\AI-Monitoring\collector\state (AIM_STATE_DIR).
  - Enrollment token (optional) is %ProgramData%\AI-Monitoring\collector\enroll-token.
  - Best-effort: a single user failure must not abort the cycle for others.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$PayloadDir = "$env:ProgramFiles\AIMonitoring\Collector"
$ConfigDir  = "$env:ProgramData\AI-Monitoring\collector"
$MachineState = Join-Path $ConfigDir 'state'
$EnrollTokenFile = Join-Path $ConfigDir 'enroll-token'

function Log($m) { Write-Host "[aim-cycle] $m" }

$Python = Join-Path $PayloadDir 'runtime\python.exe'
if (-not (Test-Path $Python)) {
  $py = Get-Command py.exe, python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if (-not $py) { Log 'no Python interpreter; aborting cycle'; exit 0 }
  $Python = $py.Source
}

$env:PYTHONPATH = $PayloadDir
$env:PYTHONDONTWRITEBYTECODE = '1'
# Managed config is discovered via ProgramData path (config.py).

# --- per-user transcript scan + spool flush ------------------------------------
# Mirrors deploy/linux/aim-collector-scan.sh: each human profile that has
# collector state or Claude settings is scanned under its own AIM_STATE_DIR so
# hooks' spools drain with the machine-wide ingest token from ProgramData.
$skip = @('Public', 'Default', 'Default User', 'All Users')
foreach ($profile in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
  if ($skip -contains $profile.Name) { continue }
  $userState = Join-Path $profile.FullName '.aim-collector'
  $claudeSettings = Join-Path $profile.FullName '.claude\settings.json'
  if (-not (Test-Path $userState) -and -not (Test-Path $claudeSettings)) { continue }

  $env:AIM_STATE_DIR = $userState
  try {
    & $Python -m aim_collector scan-once 2>$null | Out-Null
    & $Python -m aim_collector flush 2>$null | Out-Null
  } catch {
    Log "scan/flush failed for $($profile.Name): $_"
  }
}

# --- machine enroll (once) + heartbeat -----------------------------------------
# Device identity is machine-scoped (SYSTEM task), not per-user, so coverage
# counts hosts not profiles.
New-Item -ItemType Directory -Force -Path $MachineState | Out-Null
$env:AIM_STATE_DIR = $MachineState

$deviceToken = Join-Path $MachineState 'device_token'
if (-not (Test-Path $deviceToken) -and (Test-Path $EnrollTokenFile)) {
  $enrollToken = (Get-Content $EnrollTokenFile -Raw -ErrorAction SilentlyContinue).Trim()
  $cfgPath = Join-Path $ConfigDir 'config.json'
  $ingestUrl = $null
  if (Test-Path $cfgPath) {
    try {
      $ingestUrl = (Get-Content $cfgPath -Raw | ConvertFrom-Json).ingest_url
    } catch { $ingestUrl = $null }
  }
  $ring = if ($env:AIM_RING) { $env:AIM_RING } else { 'ring0' }
  if ($enrollToken -and $ingestUrl) {
    Log "enrolling machine against $ingestUrl (ring=$ring)"
    & $Python -m aim_collector install `
      --ingest-url $ingestUrl `
      --enroll-token $enrollToken `
      --ring $ring 2>&1 | ForEach-Object { Log $_ }
  }
}

try {
  $hb = & $Python -m aim_collector heartbeat 2>&1
  $hb | ForEach-Object { Log $_ }
} catch {
  Log "heartbeat failed: $_"
}

exit 0
