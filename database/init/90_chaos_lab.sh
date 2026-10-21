#!/usr/bin/env bash
# =============================================================================
# PROJECT RESILIENCE-ALPHA — 90 : primitives du laboratoire d'injection de pannes
# -----------------------------------------------------------------------------
# Installé UNIQUEMENT si CHAOS_LAB_ENABLED=true (environnement de démonstration).
# Simule une attaque par altération directe des soldes, contournant le grand
# livre : c'est exactement ce que les invariants I4/C3 doivent détecter et que
# le playbook PB-INTEGRITY-RESTORE doit corriger.
# =============================================================================
set -euo pipefail

if [ "${CHAOS_LAB_ENABLED:-false}" != "true" ]; then
  echo "[90_chaos_lab] CHAOS_LAB_ENABLED != true : primitives de laboratoire non installées"
  exit 0
fi

client=(mariadb --batch --user="${MARIADB_ADMIN_USER:-root}")
if [ -n "${MARIADB_ADMIN_HOST:-}" ]; then
  client+=(--host="$MARIADB_ADMIN_HOST" --port="${MARIADB_ADMIN_PORT:-3306}")
fi
export MYSQL_PWD="${MARIADB_ADMIN_PASSWORD:-${MARIADB_ROOT_PASSWORD:-}}"

"${client[@]}" <<'EOSQL'
SET sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';
DELIMITER $$
CREATE DEFINER = 'ra_owner'@'localhost' PROCEDURE ra_payment.sp_lab_tamper_balance(IN p_account_number VARCHAR(12), IN p_delta_minor BIGINT)
MODIFIES SQL DATA SQL SECURITY DEFINER
COMMENT 'LABORATOIRE UNIQUEMENT — altère un solde sans écriture au grand livre'
BEGIN
    DECLARE v_account_id CHAR(36);
    DECLARE v_msg VARCHAR(128);
    IF p_delta_minor IS NULL OR p_delta_minor = 0 THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = '22023 delta must be non-zero';
    END IF;
    SELECT id INTO v_account_id FROM ra_payment.accounts WHERE account_number = p_account_number;
    IF v_account_id IS NULL THEN
        SET v_msg = CONCAT('RA001 account ', p_account_number, ' not found');
        SIGNAL SQLSTATE 'RA001' SET MESSAGE_TEXT = v_msg;
    END IF;
    UPDATE ra_payment.account_balances SET available_minor = available_minor + p_delta_minor WHERE account_id = v_account_id;
    SELECT available_minor FROM ra_payment.account_balances WHERE account_id = v_account_id;
END $$
DELIMITER ;
GRANT EXECUTE ON PROCEDURE ra_payment.sp_lab_tamper_balance TO ra_payment_maint_role;
EOSQL
echo "[90_chaos_lab] primitives de laboratoire installées (NE PAS ACTIVER EN PRODUCTION)"
