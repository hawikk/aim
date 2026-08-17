#requires -Version 5.1
<#
.SYNOPSIS
  Bridge: after the Windows Intune app is on the host, enroll each WSL distro
  with the Linux collector path.

.DESCRIPTION
  Invoked as an Intune remediation / dependency script (SYSTEM). For every
  non-docker WSL distro it copies deploy/linux assets in via `wsl` and runs
  install.sh with the same ring secrets the Windows host already has.

.PARAMETER IngestUrl
  Ingestion base URL (required if not already in ProgramData config).

.PARAMETER Distros
  Optional explicit list. Default: all registered WSL distros except docker-*.

.NOTES
  Requires WSL2. Linux install needs python3 inside the distro (standard on
  Ubuntu/RHEL stock images). Failures are logged and non-fatal so a broken
  distro does not block the Windows host enrollment.
#>
[CmdletBinding()]
param(
  [string]$IngestUrl,
  [string[]]$Distros,
  [string]$Ring = 'ring0'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$ConfigDir = "$env:ProgramData\AI-Monitoring\collector"
$RepoLinux = Join-Path $PSScriptRoot '..\linux'
# When staged inside the intunewin package, linux assets ship under wsl-linux\.
if (-not (Test-Path (Join-Path $RepoLinux 'install.sh'))) {
  $RepoLinux = Join-Path $PSScriptRoot 'wsl-linux'
}

function Log($m) { Write-Host "[aim-wsl] $m" }

if (-not (Get-Command wsl.exe -ErrorAction SilentlyContinue)) {
  Log 'wsl.exe not present; skipping WSL install path'
  exit 0
}

if (-not $IngestUrl -and (Test-Path (Join-Path $ConfigDir 'config.json'))) {
  try {
    $IngestUrl = (Get-Content (Join-Path $ConfigDir 'config.json') -Raw | ConvertFrom-Json).ingest_url
  } catch { }
}
if (-not $IngestUrl) {
  Log 'no IngestUrl; cannot enroll WSL distros'
  exit 0
}

$Token = $null
$tokenFile = Join-Path $ConfigDir 'token'
if (Test-Path $tokenFile) {
  $Token = (Get-Content $tokenFile -Raw).Trim()
}
$EnrollToken = $null
$enrollFile = Join-Path $ConfigDir 'enroll-token'
if (Test-Path $enrollFile) {
  $EnrollToken = (Get-Content $enrollFile -Raw).Trim()
}
if (-not $Token) {
  Log 'no machine ingest token in ProgramData; skipping WSL'
  exit 0
}

if (-not (Test-Path (Join-Path $RepoLinux 'install.sh'))) {
  Log "linux install assets not found at $RepoLinux; skip"
  exit 0
}

if (-not $Distros -or $Distros.Count -eq 0) {
  $raw = & wsl.exe -l -q 2>$null
  $Distros = @($raw | ForEach-Object { $_.ToString().Trim() } |
    Where-Object { $_ -and $_ -notmatch '^(docker-desktop|docker-desktop-data)' })
}

foreach ($d in $Distros) {
  if (-not $d) { continue }
  Log "installing into WSL distro: $d"
  # Stage linux assets into a temp dir inside the distro, then run install.
  $stage = "/tmp/aim-collector-stage-$$"
  try {
    & wsl.exe -d $d -- bash -lc "rm -rf $stage && mkdir -p $stage" 2>$null
    # Copy via tar over stdin so we don't depend on a shared Windows path mount.
    $tar = Join-Path $env:TEMP "aim-wsl-$d.tar"
    if (Get-Command tar.exe -ErrorAction SilentlyContinue) {
      Push-Location $RepoLinux
      & tar.exe -cf $tar install.sh uninstall.sh aim-collector-scan.sh aim-collector-heartbeat.sh systemd 2>$null
      Pop-Location
      Get-Content $tar -AsByteStream -ErrorAction SilentlyContinue | & wsl.exe -d $d -- bash -lc "cat > $stage/bundle.tar && cd $stage && tar -xf bundle.tar"
      Remove-Item $tar -Force -ErrorAction SilentlyContinue
    } else {
      # Fallback: rely on /mnt/c path when the package is on a Windows drive.
      $winPath = (Resolve-Path $RepoLinux).Path -replace '\\', '/' -replace '^([A-Za-z]):', { '/mnt/' + $_.Groups[1].Value.ToLower() }
      & wsl.exe -d $d -- bash -lc "cp -a '$winPath'/. $stage/"
    }

    $envArgs = "AIM_INGEST_URL='$IngestUrl' AIM_TOKEN='$Token' AIM_RING='$Ring'"
    if ($EnrollToken) { $envArgs += " AIM_ENROLL_TOKEN='$EnrollToken'" }
    # Prefer staged payload next to install.sh (intunewin layout); install.sh
    # also accepts AIM_PAYLOAD_SRC / monorepo default.
    $envArgs += " AIM_PAYLOAD_SRC='$stage/payload/aim_collector'"
    & wsl.exe -d $d -- bash -lc "cd $stage && sudo $envArgs bash ./install.sh"
    Log "WSL distro $d install finished (exit $LASTEXITCODE)"
  } catch {
    Log "WSL distro $d failed: $_"
  }
}

exit 0
