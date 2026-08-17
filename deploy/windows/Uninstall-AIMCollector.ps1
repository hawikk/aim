#requires -Version 5.1
<#
.SYNOPSIS
  AI Monitoring collector uninstaller for Windows (AIM-28). Runs as SYSTEM.
  Removes scheduled task, hooks, payload, config, and the detection key;
  verifies no residue and exits 1 if anything remains.

.PARAMETER PurgeState
  Also remove per-user state (~\.aim-collector) from every profile.
#>
[CmdletBinding()]
param([switch]$PurgeState)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'   # best-effort removal, residue check decides

$PayloadDir = "$env:ProgramFiles\AIMonitoring\Collector"
$ConfigDir  = "$env:ProgramData\AI-Monitoring\collector"
$RegKey     = 'HKLM:\SOFTWARE\AIMonitoring\Collector'
$TaskName   = 'AIM Collector Scan'

function Log($m) { Write-Host "[aim-uninstall] $m" }

# --- scheduled task ------------------------------------------------------------
Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
Log "scheduled task removed (if present)"

# --- per-user hook removal -------------------------------------------------------
$Python = Join-Path $PayloadDir 'runtime\python.exe'
if (-not (Test-Path $Python)) {
  $py = Get-Command py.exe, python.exe -ErrorAction SilentlyContinue | Select-Object -First 1
  if ($py) { $Python = $py.Source }
}
foreach ($profile in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
  $settings = Join-Path $profile.FullName '.claude\settings.json'
  if (-not (Test-Path $settings)) { continue }
  if (Test-Path $Python) {
    $env:AIM_CLAUDE_SETTINGS = $settings
    $env:PYTHONPATH = $PayloadDir
    & $Python -m aim_collector uninstall | Out-Null
  }
  # Fallback if payload/python already gone: strip marker entries inline.
  if ((Test-Path $settings) -and ((Get-Content $settings -Raw) -match 'aim_collector')) {
    $json = Get-Content $settings -Raw | ConvertFrom-Json
    foreach ($hookSet in @($json.hooks.PSObject.Properties)) {
      $hookSet.Value = @($hookSet.Value | Where-Object { ($_.hooks | ConvertTo-Json) -notmatch 'aim_collector' })
    }
    $json | ConvertTo-Json -Depth 20 | Set-Content $settings
  }
  Log "hooks removed for profile $($profile.Name)"
}
Remove-Item Env:AIM_CLAUDE_SETTINGS, Env:PYTHONPATH -ErrorAction SilentlyContinue

# --- payload, config, registry ----------------------------------------------------
Remove-Item -Recurse -Force $PayloadDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $ConfigDir -ErrorAction SilentlyContinue
Remove-Item -Recurse -Force $RegKey -ErrorAction SilentlyContinue
if ($PurgeState) {
  foreach ($profile in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
    Remove-Item -Recurse -Force (Join-Path $profile.FullName '.aim-collector') -ErrorAction SilentlyContinue
  }
}
Log 'payload, config, and detection key removed'

# --- residue verification -------------------------------------------------------------
$residue = @()
foreach ($p in @($PayloadDir, $ConfigDir, $RegKey)) {
  if (Test-Path $p) { $residue += $p }
}
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) { $residue += "task:$TaskName" }
if ($PurgeState) {
  foreach ($profile in (Get-ChildItem "$env:SystemDrive\Users" -Directory -ErrorAction SilentlyContinue)) {
    $s = Join-Path $profile.FullName '.aim-collector'
    if (Test-Path $s) { $residue += $s }
  }
}
if ($residue.Count -gt 0) {
  Write-Error "[aim-uninstall] FAILED, residue: $($residue -join ', ')"
  exit 1
}
Log 'uninstall complete, no residue'
exit 0
