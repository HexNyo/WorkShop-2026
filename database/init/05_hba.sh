#!/usr/bin/env bash
# =============================================================================
# PROJECT RESILIENCE-ALPHA — 05 : politique d'authentification réseau (pg_hba)
# -----------------------------------------------------------------------------
#  * Le superutilisateur n'est JAMAIS joignable par le réseau (socket local
#    uniquement, authentification peer => `docker exec` requis).
#  * Seuls les rôles applicatifs se connectent par TCP, en SCRAM-SHA-256.
#  * Tout le reste est rejeté explicitement.
# Pris en compte au redémarrage qui suit l'initialisation.
# =============================================================================
set -euo pipefail

if [ "${POSTGRES_USER}" = "postgres" ]; then
  local_superuser_line="local   all   postgres                                                   peer"
else
  local_superuser_line="local   all   ${POSTGRES_USER}                                            scram-sha-256"
fi

cat > "${PGDATA}/pg_hba.conf" <<EOF
# TYPE  DATABASE  USER                                                ADDRESS   METHOD
${local_superuser_line}
local   all   auth_app,payment_app,payment_maint,remediation_app                    scram-sha-256
local   all   all                                                                    reject
host    all   ${POSTGRES_USER}                                          all          reject
host    all   ra_owner                                                  all          reject
host    all   auth_app,payment_app,payment_maint,remediation_app        all          scram-sha-256
host    all   all                                                       all          reject
EOF

echo "[05_hba] pg_hba.conf durci (superutilisateur local uniquement)"
