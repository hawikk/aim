#requires -Version 5.1
<#
.SYNOPSIS
  AIM-745 — golden-image prepare for Windows corporate templates.

.DESCRIPTION
  Installs the collector payload + scheduled task at image build time.
  Does not leave a durable device identity when -Seal is set (default).

  Prefer the Intune Win32 path (AIM-742) for day-2 fleet; use this when
  imaging teams bake software into a golden VHD / WIM before Sysprep.

.PARAMETER IngestUrl
  Ingestion base URL.

.PARAMETER Token / TokenFile
  Events bearer (pilot ring token).

.PARAMETER EnrollToken / EnrollTokenFile
  Optional ring enrollment token for zero-touch first-boot enroll.

.PARAMETER Ring
  Enrollment ring label (default ring0).

.PARAMETER Seal
  Run Seal-ForClone.ps1 after install (default: $true).

.PARAMETER StagingDir
  Directory that already contains Install-AIMCollector.ps1 + payload\
  (output of deploy/windows/stage-intunewin.sh, or a copied tree).
#>
[CmdletBinding()]
param(
  [Parameter(Mandatory = $true)][string]$IngestUrl,
  [string]$Token,
  [string]$TokenFile,
  [string]$EnrollToken,
  [string]$EnrollTokenFile,
  [string]$Ring = 'ring0',
  [string]$Version = '0.1.0',
  [string]$HashSalt = '',
  [string]$StagingDir = '',
  [bool]$Seal = $true
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Log($m) { Write-Host "[aim-prepare-image] $m" }

$Here = $PSScriptRoot
if (-not $StagingDir) {
  # Prefer staged Intune tree next to this script, else deploy/windows.
  $candidates = @(
    (Join-Path $Here '..\windows\out\staging'),
    (Join-Path $Here '..\windows')
  )
  foreach ($c in $candidates) {
    $full = [System.IO.Path]::GetFullPath($c)
    if (Test-Path (Join-Path $full 'Install-AIMCollector.ps1')) {
      $StagingDir = $full
      break
    }
  }
}
if (-not $StagingDir -or -not (Test-Path (Join-Path $StagingDir 'Install-AIMCollector.ps1'))) {
  throw "StagingDir with Install-AIMCollector.ps1 not found. Run deploy/windows/stage-intunewin.sh first, or pass -StagingDir."
}

Log "staging: $StagingDir"
$install = Join-Path $StagingDir 'Install-AIMCollector.ps1'
$args = @{
  IngestUrl = $IngestUrl
  Ring      = $Ring
  Version   = $Version
  HashSalt  = $HashSalt
}
if ($Token) { $args.Token = $Token }
if ($TokenFile) { $args.TokenFile = $TokenFile }
if ($EnrollToken) { $args.EnrollToken = $EnrollToken }
if ($EnrollTokenFile) { $args.EnrollTokenFile = $EnrollTokenFile }

# Install-AIMCollector may attempt live enroll; Seal strips identity after.
& $install @args
if ($LASTEXITCODE -and $LASTEXITCODE -ne 0) {
  throw "Install-AIMCollector.ps1 failed with exit $LASTEXITCODE"
}

# Copy first-boot + seal helpers next to payload for RunOnce / MDM.
$PayloadDir = "$env:ProgramFiles\AIMonitoring\Collector"
New-Item -ItemType Directory -Force -Path $PayloadDir | Out-Null
Copy-Item -Force (Join-Path $Here 'Seal-ForClone.ps1') $PayloadDir
Copy-Item -Force (Join-Path $Here 'FirstBoot-Enroll.ps1') $PayloadDir
Log "helpers copied to $PayloadDir"

$ConfigDir = "$env:ProgramData\AI-Monitoring\collector"
New-Item -ItemType Directory -Force -Path $ConfigDir | Out-Null
Set-Content -Path (Join-Path $ConfigDir 'image-state') -Value 'prepared' -NoNewline

if ($Seal) {
  Log 'sealing identity for Sysprep / capture'
  & (Join-Path $Here 'Seal-ForClone.ps1')
}

Log 'prepare-image complete — capture golden image after Sysprep generalize'
