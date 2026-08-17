#requires -Version 5.1
<#
.SYNOPSIS
  strip per-device identity before Sysprep / golden VHD capture.

.DESCRIPTION
  Removes host_id + device_token under the machine state dir and per-user
  collector state. Preserves payload, managed config, ring secrets, and
  the scheduled task. Fail-closed if identity files remain.

  Run as SYSTEM / Administrator on the template host after prepare-image
  and before Sysprep /generalize.
#>
[CmdletBinding()]
param(
  [string]$ConfigDir = "$env:ProgramData\AI-Monitoring\collector",
  [switch]$PurgeUserState
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Log($m) { Write-Host "[aim-seal] $m" }

$MachineState = Join-Path $ConfigDir 'state'
$identityNames = @('host_id', 'device_token', 'device-token', 'device_id', 'last_heartbeat')

function Clear-IdentityDir([string]$dir) {
  if (-not (Test-Path $dir)) { return }
  foreach ($n in $identityNames) {
    $p = Join-Path $dir $n
    if (Test-Path $p) {
      Remove-Item -Force $p
      Log "removed $p"
    }
  }
}

New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
Clear-IdentityDir $ConfigDir
Clear-IdentityDir $MachineState

# Per-user state
$skip = @('Public', 'Default', 'Default User', 'All Users')
foreach ($profile in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
  if ($skip -contains $profile.Name) { continue }
  $userState = Join-Path $profile.FullName '.aim-collector'
  if (-not (Test-Path $userState)) { continue }
  if ($PurgeUserState -or $true) {
    # Default: purge entire user state from template (spools are not the clone's).
    Remove-Item -Recurse -Force $userState
    Log "purged $userState"
  } else {
    Clear-IdentityDir $userState
  }
}

Set-Content -Path (Join-Path $ConfigDir 'image-state') -Value 'sealed' -NoNewline
New-Item -ItemType File -Force -Path (Join-Path $ConfigDir 'needs-enroll') | Out-Null
Log 'image-state=sealed, needs-enroll marker set'

# Fail-closed
$leaked = @()
foreach ($n in $identityNames) {
  foreach ($base in @($ConfigDir, $MachineState)) {
    $p = Join-Path $base $n
    if (Test-Path $p) { $leaked += $p }
  }
}
if ($leaked.Count -gt 0) {
  throw "seal incomplete — identity still present: $($leaked -join ', ')"
}

Log 'seal complete — safe to Sysprep / capture'
exit 0
