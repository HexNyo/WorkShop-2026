# syntax=docker/dockerfile:1.7
# =============================================================================
# PROJECT RESILIENCE-ALPHA — instance MariaDB jetable pour les tests d'acceptation
# (scripts/test-database.sh). En exploitation, la base est une instance MariaDB
# externe initialisée par database/apply.sh : cette image n'est jamais déployée.
# =============================================================================
ARG MARIADB_IMAGE=mariadb:11.4.4

FROM ${MARIADB_IMAGE}
LABEL org.opencontainers.image.title="resilience-alpha-database-test" \
      org.opencontainers.image.description="MariaDB — bases ra_auth / ra_payment / ra_remediation + suite d'acceptation" \
      org.opencontainers.image.version="1.0.0"
# Exécutables : l'entrypoint les lance au lieu de les « sourcer » dans son propre shell.
COPY --chown=root:root --chmod=0755 init/ /docker-entrypoint-initdb.d/
COPY --chown=root:root --chmod=0755 tests/ /tests/
