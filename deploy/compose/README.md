# Compose overrides — pilot pull path (AIM-1126)

| File | Role |
| --- | --- |
| `docker-compose.pilot.yml` | Keep only the pilot control-plane services (skip gatehouse/sentinel/hygiene-cron/shadow-ai builds) |
| `docker-compose.pull.yml` | Pin GHCR images; clear `build:` with Compose v2 `!reset` |
| `images.pin.env.example` | Tag/digest pin template — copy to `images.pin.env` |

Operator guide: [`docs/deployment/prebuilt-images.md`](../../docs/deployment/prebuilt-images.md).

## Quick use

```bash
# Tag mode (after docker login ghcr.io if packages are private)
export AIM_IMAGE_TAG=main-<shortsha>   # from release-images run
./scripts/install-pilot.sh --pull

# Digest mode
set -a; . deploy/compose/images.pin.env; set +a
./scripts/install-pilot.sh --pull

# Contributors: source build still works
./scripts/install-pilot.sh --build
```
