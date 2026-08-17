# Build the shadow-ai service from the repo root:
#   docker compose build shadow-ai
FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY services/shadow-ai/pyproject.toml services/shadow-ai/README.md ./
COPY services/shadow-ai/src ./src
COPY services/shadow-ai/catalogue ./catalogue
COPY services/shadow-ai/fixtures ./fixtures
RUN pip install --no-cache-dir . \
    && pip uninstall -y pip setuptools
# After pip install, package code lives under site-packages — not next to
# /app/catalogue and /app/fixtures. Pin absolute defaults so the
# image boots without compose overrides or dogfood env patches.
ENV SHADOW_AI_CATALOGUE_PATH=/app/catalogue/ai-tools.json \
    SHADOW_AI_GRANT_FIXTURE_PATH=/app/fixtures/oauth_grants.json \
    SHADOW_AI_PROXY_FIXTURE_PATH=/app/fixtures/proxy_observations.json \
    SHADOW_AI_PROCESS_FIXTURE_PATH=/app/fixtures/process_observations.json
RUN useradd --create-home app && mkdir -p /app/data && chown -R app:app /app
USER app
EXPOSE 8090
# Fixture-backed IdP grant sync (dogfood), then serve ops API. Live Entra/Okta
# sources are selected via SHADOW_AI_GRANT_SOURCE without rebuilding.
CMD ["sh", "-c", "shadow-ai sync && shadow-ai serve"]
