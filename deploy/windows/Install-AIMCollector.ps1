#requires -Version 5.1
<#
.SYNOPSIS
  AI Monitoring collector installer for Windows (AIM-28 / AIM-742), packaged
  as an Intune Win32 app. Runs as SYSTEM. Non-interactive, idempotent.

.PARAMETER IngestUrl
  Ingestion base URL (required).

.PARAMETER Token
  Ingest bearer token (pilot: pre-shared per ring). Alternatively pass
  -TokenFile. This is the events token (/v1/events) — not the enrollment
  secret.

.PARAMETER EnrollToken
  Optional scoped enrollment token (from the dashboard Onboarding mint).
  When set, written next to config and used for a one-shot /v1/enroll so
  the device appears in Fleet coverage (parity with Linux AIM_ENROLL_TOKEN).
  Alternatively pass -EnrollTokenFile.

.PARAMETER Ring
  Enrollment ring label (default ring0). Written to the detection registry
  key for fleet inventory.

.PARAMETER HashSalt
  Org-wide HMAC pseudonymization salt (must match ingestion side).

.LAYOUT
  C:\Program Files\AIMonitoring\Collector\   payload (aim_collector + cycle script + optional runtime\)
  C:\ProgramData\AI-Monitoring\collector\    config.json + token + enroll-token (ACL: SYSTEM + Administrators only)
  C:\ProgramData\AI-Monitoring\collector\state\  machine host_id + device_token
  HKLM\SOFTWARE\AIMonitoring\Collector       detection key (Version, Ring)
  Scheduled task "AIM Collector Scan"        SYSTEM, every 5 min: per-user scan/flush + heartbeat

.RETURN CODES
  0 success, 1 failure, 1618 retry (another install in progress)
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$IngestUrl,
  [string]$Token,
  [string]$TokenFile,
  [string]$EnrollToken,
  [string]$EnrollTokenFile,
  [string]$HashSalt = '',
  [string]$Ring = 'ring0',
  [string]$Version = '0.1.0'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$PayloadDir = "$env:ProgramFiles\AIMonitoring\Collector"
$ConfigDir  = "$env:ProgramData\AI-Monitoring\collector"
$MachineState = Join-Path $ConfigDir 'state'
$RegKey     = 'HKLM:\SOFTWARE\AIMonitoring\Collector'
$TaskName   = 'AIM Collector Scan'
$Source     = $PSScriptRoot   # Intune staging dir: contains payload\ + runtime\ (optional)

function Log($m) { Write-Host "[aim-install] $m" }

try {
  if (-not $Token -and $TokenFile) { $Token = (Get-Content $TokenFile -Raw).Trim() }
  if (-not $Token) { throw 'no token: pass -Token or -TokenFile' }
  if (-not $EnrollToken -and $EnrollTokenFile -and (Test-Path $EnrollTokenFile)) {
    $EnrollToken = (Get-Content $EnrollTokenFile -Raw).Trim()
  }

  # --- payload ---------------------------------------------------------------
  New-Item -ItemType Directory -Force -Path $PayloadDir | Out-Null
  if (-not (Test-Path "$Source\payload\aim_collector")) {
    throw "payload\aim_collector missing from package (run deploy/windows/stage-intunewin.sh)"
  }
  Copy-Item -Recurse -Force "$Source\payload\aim_collector" $PayloadDir
  # Cycle script must live next to the payload so the scheduled task is stable
  # across package rebuilds that only change collector code.
  if (Test-Path (Join-Path $Source 'Invoke-AIMCollectorCycle.ps1')) {
    Copy-Item -Force (Join-Path $Source 'Invoke-AIMCollectorCycle.ps1') $PayloadDir
  }
  if (Test-Path "$Source\runtime") {
    Copy-Item -Recurse -Force "$Source\runtime" $PayloadDir
  }
  Log "payload installed to $PayloadDir"

  # Interpreter: bundled runtime if present, else system Python Launcher.
  $Python = Join-Path $PayloadDir 'runtime\python.exe'
  if (-not (Test-Path $Python)) {
    $py = Get-Command py.exe, python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $py) { throw 'no Python interpreter found and no bundled runtime\ in package' }
    $Python = $py.Source
  }
  Log "interpreter: $Python"

  # --- config (ACL: SYSTEM + Administrators) -----------------------------------
  New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
  New-Item -ItemType Directory -Force -Path $MachineState | Out-Null
  $tokenPath = Join-Path $ConfigDir 'token'
  $config = @{
    ingest_url = $IngestUrl
    token_file = $tokenPath
    hash_salt  = $HashSalt
  } | ConvertTo-Json
  [System.IO.File]::WriteAllText((Join-Path $ConfigDir 'config.json'), $config)
  [System.IO.File]::WriteAllText($tokenPath, $Token)

  # Optional scoped enrollment token (AIM-744 parity with Linux AIM_ENROLL_TOKEN).
  # Written next to config so the cycle can re-enroll; also used immediately
  # below for a one-shot enroll so Fleet sees the device now.
  if ($EnrollToken) {
    [System.IO.File]::WriteAllText((Join-Path $ConfigDir 'enroll-token'), $EnrollToken)
    Log "enrollment token written (device will enroll + heartbeat)"
  }

  # Endpoint enforcement bundle (AIM-110 / AIM-296; delivery gap closed in AIM-440).
  # Without this file the collector fail-opens to observe while policy claims enforce.
  $enforceCandidates = @(
    (Join-Path $Source 'enforcement\enforcement.enforce.json'),
    (Join-Path $Source 'payload\aim_collector\default_enforcement.json'),
    (Join-Path $PayloadDir 'aim_collector\default_enforcement.json')
  )
  $enforceSrc = $enforceCandidates | Where-Object { Test-Path $_ } | Select-Object -First 1
  if ($enforceSrc) {
    Copy-Item -Force $enforceSrc (Join-Path $ConfigDir 'enforcement.json')
    Log "enforcement bundle installed to $ConfigDir\enforcement.json"
  } else {
    Log "WARNING: enforcement bundle not found — endpoint will fail-open to observe"
  }

  $acl = Get-Acl $ConfigDir
  $acl.SetAccessRuleProtection($true, $false)   # disable inheritance
  $acl.Access | ForEach-Object { $acl.RemoveAccessRule($_) | Out-Null }
  foreach ($id in @('NT AUTHORITY\SYSTEM', 'BUILTIN\Administrators')) {
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
      $id, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')
    $acl.AddAccessRule($rule)
  }
  Set-Acl $ConfigDir $acl
  Log "config written to $ConfigDir (ACL: SYSTEM + Administrators)"

  # --- per-user hook registration ----------------------------------------------
  # Hooks run as the engineer; they spool locally if the ACL'd token is
  # unreadable — the SYSTEM cycle task drains spools with the token.
  $hookCommand = "`"$Python`" -m aim_collector hook"
  foreach ($profile in (Get-ChildItem "$env:SystemDrive\Users" -Directory)) {
    $settings = Join-Path $profile.FullName '.claude\settings.json'
    if (-not (Test-Path (Split-Path $settings))) { continue }  # not a Claude Code user (yet)
    $env:AIM_CLAUDE_SETTINGS = $settings
    $env:AIM_HOOK_COMMAND = $hookCommand
    $env:PYTHONPATH = $PayloadDir
    & $Python -m aim_collector install | Out-Null
    Log "hooks registered for profile $($profile.Name)"
  }
  Remove-Item Env:AIM_CLAUDE_SETTINGS, Env:AIM_HOOK_COMMAND -ErrorAction SilentlyContinue

  # --- machine enroll (optional, best-effort at install time) ------------------
  # Same protocol as `python3 -m aim_collector install --enroll-token` on Linux.
  # Transient network failure must not fail the Intune install — the enroll-token
  # file remains for the cycle task to retry.
  if ($EnrollToken) {
    $env:PYTHONPATH = $PayloadDir
    $env:AIM_STATE_DIR = $MachineState
    $env:AIM_RING = $Ring
    try {
      & $Python -m aim_collector install `
        --ingest-url $IngestUrl `
        --enroll-token $EnrollToken `
        --ring $Ring 2>&1 | ForEach-Object { Log "enroll: $_" }
      Log "device enroll attempted (check Fleet within one heartbeat ≤5 min)"
    } catch {
      Log "WARNING: enroll failed (will retry later): $_"
    }
  }

  # --- scheduled cycle task (SYSTEM, every 5 min) ------------------------------
  # AIM-624 / AIM-643 / AIM-742: per-user scan+flush + machine enroll/heartbeat
  # so enrolled Windows devices appear in fleet coverage.
  $cycleScript = Join-Path $PayloadDir 'Invoke-AIMCollectorCycle.ps1'
  if (-not (Test-Path $cycleScript)) {
    # Last-resort inline cycle if the helper was not packaged.
    $scanCmd = "`$env:PYTHONPATH='$PayloadDir'; `"$Python`" -m aim_collector scan-once; `"$Python`" -m aim_collector flush; `"$Python`" -m aim_collector heartbeat"
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
      -Argument "-NoProfile -WindowStyle Hidden -Command `"$scanCmd`""
  } else {
    $action = New-ScheduledTaskAction -Execute 'powershell.exe' `
      -Argument "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$cycleScript`""
  }
  $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) `
    -RepetitionInterval (New-TimeSpan -Minutes 5)
  $principal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
    -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
  Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger `
    -Principal $principal -Settings $settings -Force | Out-Null
  Log "scheduled task '$TaskName' registered (SYSTEM, 5 min; scan+flush+heartbeat)"

  # --- detection key -----------------------------------------------------------
  New-Item -Path $RegKey -Force | Out-Null
  Set-ItemProperty $RegKey -Name Version -Value $Version
  Set-ItemProperty $RegKey -Name InstallDate -Value (Get-Date -Format 'yyyy-MM-dd')
  Set-ItemProperty $RegKey -Name Ring -Value $Ring
  Log "detection key $RegKey Version=$Version Ring=$Ring"

  Log 'install complete'
  exit 0
} catch {
  Write-Error "[aim-install] FAILED: $_"
  exit 1
}
