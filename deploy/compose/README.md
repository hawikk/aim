# Compose overrides — pilot pull path

| File | Role |
| --- | --- |
| `docker-compose.pilot.yml` | Keep only the pilot control-plane services (skip gatehouse/sentinel/hygiene-cron/shadow-ai builds) |
| `docker-compose.pull.yml` | Pin GHCR images; clear `build:` with Compose v2 `!reset` |
| `images.pin.env.example` | Tag/digest pin template — copy to `images.pin.env` |

Operator guide: [`docs/deployment/prebuilt-images.md`](../../docs/deployment/prebuilt-images.md).

> The pull path needs a registry that actually holds the images. No images are
> published for this public snapshot, so strict `--pull` fails against the
> default `ghcr.io/hawikk/aim-*` coordinates until you push your own and set
> `AIM_IMAGE_REGISTRY`. Bare `install-pilot.sh` is unaffected: it defaults to
> `prefer-pull` and falls back to a source build.

## Quick use

```bash
# Tag mode (after docker login ghcr.io if packages are private)
export AIM_IMAGE_TAG=main-<shortsha>   # from the release-images run
./scripts/install-pilot.sh --pull

# Digest mode
set -a; . deploy/compose/images.pin.env; set +a
./scripts/install-pilot.sh --pull

# Contributors: source build still works
./scripts/install-pilot.sh --build
```
