#!/usr/bin/env bash
# =============================================================================
# PROJECT RESILIENCE-ALPHA — 00 : comptes MariaDB et rôles (moindre privilège)
# -----------------------------------------------------------------------------
# Exécuté une seule fois avec un compte administrateur (cf. database/apply.sh).
# Aucun secret dans ce fichier : les mots de passe sont lus dans l'environnement.
#
#   ra_owner@localhost   verrouillé   DEFINER des déclencheurs, vues et procédures
#   ra_auth_app          auth-service       -> base ra_auth uniquement
#   ra_payment_app       payment-api        -> ra_payment (runtime)
#   ra_payment_maint     payment-api        -> procédures de maintenance
#   ra_remediation_app   remediation-engine -> ra_remediation
# Les droits sont portés par des rôles (<compte>_role) accordés table par table
# dans 01-03 ; les comptes ne se connectent que depuis RA_DB_CLIENT_HOST.
# =============================================================================
set -euo pipefail

fatal() { echo "FATAL: $*" >&2; exit 1; }

for var in RA_DB_AUTH_PASSWORD RA_DB_PAYMENT_PASSWORD RA_DB_PAYMENT_MAINT_PASSWORD RA_DB_REMEDIATION_PASSWORD; do
  value="${!var:-}"
  [ "${#value}" -ge 16 ] || fatal "${var} absente ou de moins de 16 caractères"
done

client=(mariadb --batch --skip-column-names --user="${MARIADB_ADMIN_USER:-root}")
if [ -n "${MARIADB_ADMIN_HOST:-}" ]; then
  client+=(--host="$MARIADB_ADMIN_HOST" --port="${MARIADB_ADMIN_PORT:-3306}")
fi
export MYSQL_PWD="${MARIADB_ADMIN_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}"

# 10.6 minimum : INSERT … RETURNING, JSON_ARRAYAGG(… LIMIT), contraintes CHECK.
version="$("${client[@]}" -e 'SELECT VERSION()')"
case "$version" in *MariaDB*) ;; *) fatal "serveur non MariaDB ($version)" ;; esac
[ "$(printf '%s\n' 10.6 "${version%%-*}" | sort -V | head -n1)" = "10.6" ] || fatal "MariaDB >= 10.6 requis ($version)"

existing="$("${client[@]}" -e "SELECT GROUP_CONCAT(schema_name) FROM information_schema.schemata WHERE schema_name IN ('ra_auth','ra_payment','ra_remediation')")"
[ "$existing" = "NULL" ] || fatal "déjà initialisée ($existing) : rien n'est modifié. Pour repartir de zéro (données perdues) : DROP DATABASE de ces bases puis relancer."

# Littéral SQL entre apostrophes (antislashs et apostrophes échappés).
q() { local s="${1//\\/\\\\}"; printf "'%s'" "${s//\'/\\\'}"; }
host="$(q "${RA_DB_CLIENT_HOST:-%}")"

account() {  # account <compte> <mot de passe> <connexions max> <durée max d'une requête (s)>
  cat <<EOF
CREATE OR REPLACE ROLE $1_role;
CREATE OR REPLACE USER '$1'@$host IDENTIFIED BY $(q "$2") WITH MAX_USER_CONNECTIONS $3 MAX_STATEMENT_TIME $4;
GRANT $1_role TO '$1'@$host;
SET DEFAULT ROLE $1_role FOR '$1'@$host;
EOF
}

{
  cat <<'EOF'
CREATE OR REPLACE USER 'ra_owner'@'localhost' ACCOUNT LOCK;
GRANT ALL PRIVILEGES ON ra_auth.* TO 'ra_owner'@'localhost';
GRANT ALL PRIVILEGES ON ra_payment.* TO 'ra_owner'@'localhost';
GRANT ALL PRIVILEGES ON ra_remediation.* TO 'ra_owner'@'localhost';
EOF
  account ra_auth_app        "$RA_DB_AUTH_PASSWORD"          30 5
  account ra_payment_app     "$RA_DB_PAYMENT_PASSWORD"       40 5
  account ra_payment_maint   "$RA_DB_PAYMENT_MAINT_PASSWORD"  5 60
  account ra_remediation_app "$RA_DB_REMEDIATION_PASSWORD"   20 10
} | "${client[@]}"

echo "[00_users] comptes applicatifs créés (hôte autorisé : ${RA_DB_CLIENT_HOST:-%})"
