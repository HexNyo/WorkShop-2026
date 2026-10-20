# syntax=docker/dockerfile:1.7
# =============================================================================
# PROJECT RESILIENCE-ALPHA — image PostgreSQL
#   runtime (défaut) : schémas + rôles + durcissement, exécution non-root
#   test             : runtime + suite d'acceptation (ne jamais déployer)
# =============================================================================
ARG POSTGRES_IMAGE=postgres:17.2-alpine3.21

FROM ${POSTGRES_IMAGE} AS base
LABEL org.opencontainers.image.title="resilience-alpha-database" \
      org.opencontainers.image.description="PostgreSQL 17 — schémas auth / payment / remediation" \
      org.opencontainers.image.version="1.0.0"
# Les scripts d'init doivent être exécutables : sinon l'entrypoint les « source »
# dans son propre shell (effets de bord sur set -u / exit).
COPY --chown=root:root --chmod=0755 init/ /docker-entrypoint-initdb.d/

FROM base AS test
COPY --chown=root:root --chmod=0755 tests/ /tests/
USER postgres

FROM base AS runtime
# L'image officielle prépare $PGDATA pour l'utilisateur postgres (uid 70) :
# aucun privilège root n'est nécessaire à l'exécution.
USER postgres
HEALTHCHECK --interval=5s --timeout=3s --start-period=30s --retries=5 \
  CMD pg_isready --host=127.0.0.1 --username="$POSTGRES_USER" --dbname="$POSTGRES_DB" --quiet || exit 1
