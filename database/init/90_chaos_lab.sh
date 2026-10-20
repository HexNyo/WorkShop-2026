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
else
psql -v ON_ERROR_STOP=1 --no-psqlrc --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<'EOSQL'
BEGIN;
SET LOCAL ROLE ra_owner;

CREATE FUNCTION payment.fn_lab_tamper_balance(p_account_id uuid, p_delta_minor bigint)
RETURNS bigint
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
DECLARE
    v_new bigint;
BEGIN
    IF p_delta_minor = 0 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'delta must be non-zero';
    END IF;
    UPDATE payment.account_balances
       SET available_minor = available_minor + p_delta_minor
     WHERE account_id = p_account_id
    RETURNING available_minor INTO v_new;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'RA001', MESSAGE = format('account %s not found', p_account_id);
    END IF;
    RETURN v_new;
END $$;

COMMENT ON FUNCTION payment.fn_lab_tamper_balance(uuid, bigint) IS 'LABORATOIRE UNIQUEMENT — altère un solde sans écriture au grand livre';
REVOKE ALL ON FUNCTION payment.fn_lab_tamper_balance(uuid, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION payment.fn_lab_tamper_balance(uuid, bigint) TO payment_maint;
COMMIT;
EOSQL
  echo "[90_chaos_lab] primitives de laboratoire installées (NE PAS ACTIVER EN PRODUCTION)"
fi
