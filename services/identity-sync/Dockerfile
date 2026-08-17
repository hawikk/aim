# Build the identity-sync service from the repo root:
#   docker compose build identity-sync
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
# Install the package first so the source layer stays cacheable.
COPY services/identity-sync/pyproject.toml services/identity-sync/README.md ./
COPY services/identity-sync/src ./src
RUN pip install --no-cache-dir . \
    # pip/setuptools are build-time only; drop them from the runtime image
    # (same CVE-surface reasoning as the ingest image dropping npm).
    && pip uninstall -y pip setuptools
# Dev directory snapshot. Compose also bind-mounts ./services/identity-sync/fixtures
# over this path (read-only) so fixture edits apply without a rebuild.
COPY services/identity-sync/fixtures ./fixtures
# Run as an unprivileged user; the service writes only its SQLite db, which
# lives under /app/data so compose can mount a named volume there (service
# identities and the reveal audit log must survive a rebuild —).
RUN useradd --create-home app && mkdir -p /app/data && chown -R app:app /app
USER app
EXPOSE 8080
# One-shot directory sync, then serve the resolution API. Sync is idempotent,
# so a container restart simply re-applies the fixture snapshot.
CMD ["sh", "-c", "identity-sync sync && identity-sync serve --host 0.0.0.0 --port 8080"]
