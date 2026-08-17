#requires -Version 5.1
<#
.SYNOPSIS
  Intune custom detection script for the AIM Collector Win32 app (AIM-28).

  Exit 0 + write output  => detected (installed)
  Exit 0 + no output     => not detected
  Non-zero               => script error (Intune retries)

.NOTES
  Prefer the registry detection rule in intunewin/README.md for production.
  This script is the fallback when a custom detection script is required
  (e.g. verifying the scheduled task exists in addition to the Version key).
#>
[CmdletBinding()]
param(
  [string]$ExpectedVersion = '0.1.0'
)
$ErrorActionPreference = 'Stop'

$RegKey = 'HKLM:\SOFTWARE\AIMonitoring\Collector'
$PayloadDir = "$env:ProgramFiles\AIMonitoring\Collector"
$TaskName = 'AIM Collector Scan'

try {
  if (-not (Test-Path $RegKey)) { exit 0 }
  $version = (Get-ItemProperty -Path $RegKey -Name Version -ErrorAction SilentlyContinue).Version
  if ($version -ne $ExpectedVersion) { exit 0 }
  if (-not (Test-Path (Join-Path $PayloadDir 'aim_collector'))) { exit 0 }
  if (-not (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue)) { exit 0 }

  # Detected: print something so Intune treats exit 0 as "found".
  Write-Output "AIM Collector $version present"
  exit 0
} catch {
  # Script error — let Intune retry rather than silently "not found".
  Write-Error $_
  exit 1
}
