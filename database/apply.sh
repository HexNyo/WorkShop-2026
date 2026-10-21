#!/usr/bin/env bash
# =============================================================================
# PROJECT RESILIENCE-ALPHA — initialisation d'une instance MariaDB existante
# -----------------------------------------------------------------------------
# Une seule fois, avec un compte administrateur (CREATE USER, GRANT, SUPER/SET USER
# pour les DEFINER) :
#   MARIADB_ADMIN_PASSWORD=... docker compose --profile init run --rm db-init
# Crée les bases ra_auth / ra_payment / ra_remediation, les comptes applicatifs
# et le jeu de démonstration. Refuse d'agir si les bases existent déjà.
# =============================================================================
set -euo pipefail

: "${MARIADB_ADMIN_HOST:?hôte MariaDB requis}"
: "${MARIADB_ADMIN_USER:?compte administrateur requis}"
: "${MARIADB_ADMIN_PASSWORD:?mot de passe administrateur requis, dans l environnement et jamais dans .env}"
export MARIADB_ADMIN_HOST MARIADB_ADMIN_USER MARIADB_ADMIN_PASSWORD
export MYSQL_PWD="$MARIADB_ADMIN_PASSWORD"

cd "$(dirname "${BASH_SOURCE[0]}")/init"
for file in *; do
  case "$file" in
    *.sh)  bash "$file" ;;
    *.sql) mariadb --batch --host="$MARIADB_ADMIN_HOST" --port="${MARIADB_ADMIN_PORT:-3306}" \
                   --user="$MARIADB_ADMIN_USER" <"$file"
           echo "[$file] appliqué" ;;
  esac
done
echo "OK: base initialisée sur $MARIADB_ADMIN_HOST"
