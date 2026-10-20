# syntax=docker/dockerfile:1.7
# =============================================================================
# PROJECT RESILIENCE-ALPHA — remediation-engine
# Contexte de build : racine du monorepo (accès à libs/python/ra_common).
#   builder : dépendances dans un virtualenv isolé
#   test    : builder + outillage de test ; les tests unitaires s'exécutent au build
#   runtime : image finale minimale, non-root, sans pip
# =============================================================================
ARG PYTHON_IMAGE=python:3.12.8-slim-bookworm

FROM ${PYTHON_IMAGE} AS base
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PATH=/opt/venv/bin:$PATH

# --------------------------------------------------------------------- builder
FROM base AS builder
RUN python -m venv /opt/venv
COPY services/remediation-engine/requirements.txt /build/requirements.txt
RUN pip install --require-virtualenv -r /build/requirements.txt
COPY libs/python/ra_common /build/ra_common
RUN pip install --require-virtualenv --no-deps /build/ra_common \
 && pip check

# ------------------------------------------------------------------------ test
FROM builder AS test
COPY services/remediation-engine/requirements-dev.txt /build/requirements-dev.txt
RUN pip install --require-virtualenv -r /build/requirements-dev.txt
WORKDIR /srv
COPY services/remediation-engine/pyproject.toml ./
COPY services/remediation-engine/app ./app
COPY services/remediation-engine/tests ./tests
RUN python -m pytest -q -p no:cacheprovider tests/unit
CMD ["python", "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests/e2e"]

# --------------------------------------------------------------------- runtime
FROM base AS runtime
LABEL org.opencontainers.image.title="resilience-alpha-remediation-engine" \
      org.opencontainers.image.description="Moteur de remédiation autonome (Zero-Touch Recovery)" \
      org.opencontainers.image.version="1.0.0"
COPY --from=builder /opt/venv /opt/venv
RUN groupadd --system --gid 10001 app \
 && useradd --system --uid 10001 --gid app --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin app \
 && rm -rf /usr/local/lib/python3.12/site-packages/pip* /usr/local/bin/pip* /opt/venv/lib/python3.12/site-packages/pip* /opt/venv/bin/pip* \
 && printf '#!/bin/sh\nexec python -m app.cli "$@"\n' > /usr/local/bin/ra-ctl \
 && chmod 0755 /usr/local/bin/ra-ctl
WORKDIR /srv
COPY --chown=root:root --chmod=0755 services/remediation-engine/app ./app
USER 10001:10001
EXPOSE 8001 8002
HEALTHCHECK --interval=10s --timeout=3s --start-period=40s --retries=3 \
  CMD ["python", "-c", "import os, sys, urllib.request; h = os.environ.get('REMEDIATION_SUPERVISION_BIND_HOST', '127.0.0.1'); p = os.environ.get('REMEDIATION_SUPERVISION_PORT', '8002'); sys.exit(0 if urllib.request.urlopen(f'http://{h}:{p}/health/liveness', timeout=2).status == 200 else 1)"]
CMD ["python", "-m", "app.main"]
