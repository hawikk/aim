# Golden-image zero-touch enrollment

Image-time install + seal + first-boot auto-enroll for corporate golden
images. Full operator recipe:

**[`docs/deployment/zero-touch-golden-image.md`](../../docs/deployment/zero-touch-golden-image.md)**

## Quick path (Linux)

```sh
# On the template host (inspect scripts first — no curl|sh):
sudo AIM_INGEST_URL=https://ingest.corp.example \
     AIM_TOKEN_FILE=/run/secrets/aim-token \
     AIM_ENROLL_TOKEN_FILE=/run/secrets/aim-enroll \
     ./deploy/golden-image/prepare-image.sh

# Capture only after seal (prepare seals by default):
#   AMI / qcow / Packer snapshot

# On each clone (optional fast path; timer also enrolls ≤5 min):
sudo /opt/aim-collector/first-boot-enroll.sh
```

## Quick path (Windows)

```powershell
# Stage payload once from the monorepo:
#   ./deploy/windows/stage-intunewin.sh

.\Prepare-GoldenImage.ps1 `
  -IngestUrl https://ingest.corp.example `
  -TokenFile C:\secrets\aim-token.txt `
  -EnrollTokenFile C:\secrets\aim-enroll.txt `
  -StagingDir ..\windows\out\staging

# Sysprep /generalize, capture VHD. On clone:
& "$env:ProgramFiles\AIMonitoring\Collector\FirstBoot-Enroll.ps1"
```

## Hard rule

Never ship `host_id` or `device_token` inside the image. `seal-for-clone`
exits non-zero if either remains.

## Proof

```sh
./scripts/golden-image-proof.sh
```
