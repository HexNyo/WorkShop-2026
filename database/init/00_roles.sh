#!/usr/bin/env bash
# =============================================================================
# PROJECT RESILIENCE-ALPHA — 00 : rôles PostgreSQL et durcissement de la base
# -----------------------------------------------------------------------------
# Exécuté une seule fois par docker-entrypoint-initdb.d (volume vierge).
# Aucun secret n'est présent dans ce fichier : les mots de passe sont lus dans
# l'environnement du conteneur via \getenv (psql >= 15), ils n'apparaissent
# donc ni dans le dépôt, ni dans la ligne de commande des processus.
#
# Modèle de moindre privilège :
#   ra_owner          NOLOGIN  propriétaire de tous les objets (migrations)
#   auth_app          LOGIN    auth-service      -> schéma auth uniquement
#   payment_app       LOGIN    payment-api       -> schéma payment (runtime)
#   payment_maint     LOGIN    payment-api       -> fonctions de maintenance
#   remediation_app   LOGIN    remediation-engine -> schéma remediation
# =============================================================================
set -euo pipefail

for var in RA_DB_AUTH_PASSWORD RA_DB_PAYMENT_PASSWORD RA_DB_PAYMENT_MAINT_PASSWORD RA_DB_REMEDIATION_PASSWORD; do
  if [ -z "${!var:-}" ]; then
    echo "FATAL: variable d'environnement ${var} absente ou vide" >&2
    exit 1
  fi
  value="${!var}"
  if [ "${#value}" -lt 16 ]; then
    echo "FATAL: ${var} doit contenir au moins 16 caractères" >&2
    exit 1
  fi
done

psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
     -v db_name="$POSTGRES_DB" <<'EOSQL'
\getenv auth_pw          RA_DB_AUTH_PASSWORD
\getenv payment_pw       RA_DB_PAYMENT_PASSWORD
\getenv payment_maint_pw RA_DB_PAYMENT_MAINT_PASSWORD
\getenv remediation_pw   RA_DB_REMEDIATION_PASSWORD

SET password_encryption = 'scram-sha-256';

-- Durcissement : personne ne se connecte ni ne crée d'objet par défaut.
REVOKE ALL ON DATABASE :"db_name" FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- Propriétaire des objets applicatifs (jamais utilisé pour se connecter).
CREATE ROLE ra_owner NOLOGIN;
GRANT CONNECT, CREATE, TEMPORARY ON DATABASE :"db_name" TO ra_owner;

-- Comptes applicatifs : un rôle par service, limites de connexion explicites.
CREATE ROLE auth_app        LOGIN PASSWORD :'auth_pw'          CONNECTION LIMIT 30;
CREATE ROLE payment_app     LOGIN PASSWORD :'payment_pw'       CONNECTION LIMIT 40;
CREATE ROLE payment_maint   LOGIN PASSWORD :'payment_maint_pw' CONNECTION LIMIT 5;
CREATE ROLE remediation_app LOGIN PASSWORD :'remediation_pw'   CONNECTION LIMIT 20;

GRANT CONNECT ON DATABASE :"db_name" TO auth_app, payment_app, payment_maint, remediation_app;

-- Garde-fous de session (protègent la base contre les requêtes/verrous orphelins).
ALTER ROLE auth_app        SET search_path = auth;
ALTER ROLE payment_app     SET search_path = payment;
ALTER ROLE payment_maint   SET search_path = payment;
ALTER ROLE remediation_app SET search_path = remediation;

ALTER ROLE auth_app        SET statement_timeout = '5s';
ALTER ROLE payment_app     SET statement_timeout = '5s';
ALTER ROLE payment_maint   SET statement_timeout = '60s';
ALTER ROLE remediation_app SET statement_timeout = '10s';

ALTER ROLE auth_app        SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE payment_app     SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE payment_maint   SET idle_in_transaction_session_timeout = '60s';
ALTER ROLE remediation_app SET idle_in_transaction_session_timeout = '30s';

ALTER ROLE payment_app     SET lock_timeout = '3s';
ALTER ROLE payment_maint   SET lock_timeout = '15s';
EOSQL

echo "[00_roles] rôles applicatifs créés"
