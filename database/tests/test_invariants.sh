#!/usr/bin/env bash
# =============================================================================
# PROJECT RESILIENCE-ALPHA — tests d'acceptation du socle de données
# Usage : scripts/test-database.sh (base éphémère, CHAOS_LAB_ENABLED=true).
# Ne jamais exécuter sur une base contenant des données à conserver.
# =============================================================================
set -uo pipefail
DB="${POSTGRES_DB:-resilience}"
FAIL=0
pw()  {
  case "$1" in
    auth_app)        printf '%s' "$RA_DB_AUTH_PASSWORD" ;;
    payment_app)     printf '%s' "$RA_DB_PAYMENT_PASSWORD" ;;
    payment_maint)   printf '%s' "$RA_DB_PAYMENT_MAINT_PASSWORD" ;;
    remediation_app) printf '%s' "$RA_DB_REMEDIATION_PASSWORD" ;;
    *)               printf '' ;;
  esac
}
q()   { PGPASSWORD="$(pw "$1")" psql -X -q -v ON_ERROR_STOP=1 -At -U "$1" -d "$DB" -c "$2" 2>&1; }
ok()  { local out; out=$(q "$1" "$3"); if [ $? -eq 0 ]; then echo "PASS  $2 -> ${out//$'\n'/ | }"; else echo "FAIL  $2 -> $out"; FAIL=1; fi; }
ko()  { local out; out=$(q "$1" "$4"); if [ $? -ne 0 ] && grep -q "$3" <<<"$out"; then echo "PASS  $2 (refusé: $3)"; else echo "FAIL  $2 -> attendu '$3', obtenu: $out"; FAIL=1; fi; }
eq()  { local out; out=$(q "$1" "$4"); if [ "$out" == "$3" ]; then echo "PASS  $2 = $3"; else echo "FAIL  $2 -> attendu '$3', obtenu '$out'"; FAIL=1; fi; }

ALICE=10000000-0000-4000-8000-000000000001
BOB=10000000-0000-4000-8000-000000000003
BOBUSD=10000000-0000-4000-8000-000000000004
SYNA=90000000-0000-4000-8000-000000000001
SYNB=90000000-0000-4000-8000-000000000002
PALICE=00000000-0000-4000-8000-000000000002
FP="'\\x$(printf 'a%.0s' {1..64})'::bytea"

echo "== Authentification réseau (pg_hba) =="
out=$(psql -X -h 127.0.0.1 -U postgres -d "$DB" -c 'SELECT 1' 2>&1)
if grep -q "rejects connection" <<<"$out"; then echo "PASS  superutilisateur refusé en TCP"; else echo "FAIL  superutilisateur TCP -> $out"; FAIL=1; fi
out=$(PGPASSWORD="$(pw payment_app)" psql -X -At -h 127.0.0.1 -U payment_app -d "$DB" -c 'SELECT current_user' 2>&1)
if [ "$out" == "payment_app" ]; then echo "PASS  rôle applicatif accepté en TCP (SCRAM)"; else echo "FAIL  rôle applicatif TCP -> $out"; FAIL=1; fi
out=$(PGPASSWORD="mauvais-mot-de-passe" psql -X -At -h 127.0.0.1 -U payment_app -d "$DB" -c 'SELECT 1' 2>&1)
if grep -q "password authentication failed" <<<"$out"; then echo "PASS  mauvais mot de passe refusé"; else echo "FAIL  mauvais mot de passe -> $out"; FAIL=1; fi

echo "== Paiement nominal =="
TX=$(q payment_app "INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint, debit_account_id, credit_account_id, amount_minor, currency) VALUES ('$PALICE','idem-0001-test',$FP,'$ALICE','$BOB',12550,'EUR') RETURNING id")
echo "tx=$TX"
ok payment_app "validation PENDING->VALIDATED" "UPDATE payment.transactions SET status='VALIDATED' WHERE id='$TX' RETURNING status"
eq payment_app "exécution atomique" "EXECUTED" "SELECT status FROM payment.fn_execute_transaction('$TX')"
eq payment_app "ré-exécution idempotente" "EXECUTED" "SELECT status FROM payment.fn_execute_transaction('$TX')"
eq payment_app "solde Alice" "487450" "SELECT available_minor FROM payment.account_balances WHERE account_id='$ALICE'"
eq payment_app "solde Bob" "262550" "SELECT available_minor FROM payment.account_balances WHERE account_id='$BOB'"
eq payment_app "historique d'états" "PENDING>VALIDATED>EXECUTED" "SELECT string_agg(to_status::text,'>' ORDER BY id) FROM payment.transaction_status_history WHERE transaction_id='$TX'"

echo "== Refus et garde-fous =="
ko payment_app "clé d'idempotence dupliquée" "uq_transactions_idempotency" "INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint, debit_account_id, credit_account_id, amount_minor, currency) VALUES ('$PALICE','idem-0001-test',$FP,'$ALICE','$BOB',1,'EUR')"
ko payment_app "devise incohérente" "currency mismatch" "INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint, debit_account_id, credit_account_id, amount_minor, currency) VALUES ('$PALICE','idem-0002-test',$FP,'$ALICE','$BOBUSD',1,'EUR')"
ko payment_app "ségrégation synthétique" "synthetic transactions" "INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint, debit_account_id, credit_account_id, amount_minor, currency, is_synthetic) VALUES ('$PALICE','idem-0003-test',$FP,'$ALICE','$SYNA',1,'EUR',true)"
TX2=$(q payment_app "INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint, debit_account_id, credit_account_id, amount_minor, currency) VALUES ('$PALICE','idem-0004-test',$FP,'$BOB','$ALICE',99999999,'EUR') RETURNING id")
q payment_app "UPDATE payment.transactions SET status='VALIDATED' WHERE id='$TX2'" >/dev/null
eq payment_app "provision insuffisante => REJECTED" "REJECTED|INSUFFICIENT_FUNDS" "SELECT status||'|'||failure_code FROM payment.fn_execute_transaction('$TX2')"
ko payment_app "transition depuis état terminal" "illegal transition" "UPDATE payment.transactions SET status='VALIDATED' WHERE id='$TX'"
TX5=$(q payment_app "INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint, debit_account_id, credit_account_id, amount_minor, currency) VALUES ('$PALICE','idem-0005-test',$FP,'$ALICE','$BOB',1,'EUR') RETURNING id")
q payment_app "UPDATE payment.transactions SET status='VALIDATED' WHERE id='$TX5'" >/dev/null
ko payment_app "EXECUTED sans écritures (contournement)" "cannot be EXECUTED" "UPDATE payment.transactions SET status='EXECUTED' WHERE id='$TX5'"
ok payment_app "annulation VALIDATED->CANCELLED" "UPDATE payment.transactions SET status='CANCELLED' WHERE id='$TX5' RETURNING status"
ko payment_app "UPDATE direct d'un solde" "permission denied" "UPDATE payment.account_balances SET available_minor=0"
ko payment_app "INSERT direct au grand livre" "permission denied" "INSERT INTO payment.ledger_entries (transaction_id, account_id, direction, amount_minor, currency) VALUES ('$TX','$ALICE','DEBIT',1,'EUR')"
ko payment_app "modification du montant" "permission denied" "UPDATE payment.transactions SET amount_minor=1 WHERE id='$TX'"
ko postgres "grand livre append-only (même superuser)" "append-only" "DELETE FROM payment.ledger_entries"
ko payment_app "accès au schéma auth" "permission denied" "SELECT * FROM auth.principals"
ko remediation_app "accès au schéma payment" "permission denied" "SELECT * FROM payment.accounts"
ko payment_app "réparation réservée à payment_maint" "permission denied" "SELECT * FROM payment.fn_repair_balances('test reason')"
ko auth_app "rôle de service sur un humain" "cannot be granted" "INSERT INTO auth.principal_roles (principal_id, role_code) VALUES ('$PALICE','svc.detector')"

echo "== Intégrité : état sain =="
eq payment_app "rapport d'intégrité (contrôles critiques)" "t" "SELECT bool_and(passed) FROM payment.fn_integrity_report() WHERE severity='CRITICAL'"

echo "== Attaque simulée : altération directe d'un solde =="
ok payment_maint "altération (laboratoire)" "SELECT payment.fn_lab_tamper_balance('$BOB', 50000)"
eq payment_app "contrôles en échec" "BALANCE_MATCHES_LEDGER,MONEY_CONSERVATION" "SELECT string_agg(check_code, ',' ORDER BY check_code) FROM payment.fn_integrity_report() WHERE NOT passed"
TX3=$(q payment_app "INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint, debit_account_id, credit_account_id, amount_minor, currency) VALUES ('$PALICE','idem-0006-test',$FP,'$ALICE','$BOB',100,'EUR') RETURNING id")
q payment_app "UPDATE payment.transactions SET status='VALIDATED' WHERE id='$TX3'" >/dev/null
ko payment_app "écriture bloquée sur compte altéré" "balance/ledger divergence" "SELECT status FROM payment.fn_execute_transaction('$TX3')"

echo "== Remédiation : reconstruction depuis le grand livre =="
eq payment_maint "simulation (dry-run)" "available_minor:312550->262550" "SELECT string_agg(field_name||':'||previous_value||'->'||corrected_value, ',') FROM payment.fn_repair_balances('incident test', NULL, true)"
ok payment_maint "réparation" "SELECT count(*) FROM payment.fn_repair_balances('incident test repair', NULL, false)"
eq payment_app "intégrité rétablie" "t" "SELECT bool_and(passed) FROM payment.fn_integrity_report() WHERE severity='CRITICAL'"
eq payment_app "transaction de nouveau possible" "EXECUTED" "SELECT status FROM payment.fn_execute_transaction('$TX3')"
eq payment_maint "purge des transactions en vol (seuil 60s)" "0" "SELECT payment.fn_fail_stale_transactions(interval '60 seconds', 'purge test')"
ok payment_maint "bascule quarantaine synthétique" "UPDATE payment.runtime_flags SET value='\"SYNTHETIC_ONLY\"', reason='test' WHERE key='write_mode' RETURNING value"
ko payment_maint "write_mode invalide" "ck_flags_value" "UPDATE payment.runtime_flags SET value='\"OPEN_BAR\"', reason='test' WHERE key='write_mode'"

echo "== Transaction synthétique =="
PSYN=00000000-0000-4000-8000-000000000102
TX4=$(q payment_app "INSERT INTO payment.transactions (initiator_principal_id, idempotency_key, request_fingerprint, debit_account_id, credit_account_id, amount_minor, currency, is_synthetic) VALUES ('$PSYN','synthetic-run1-fwd',$FP,'$SYNA','$SYNB',1,'EUR',true) RETURNING id")
q payment_app "UPDATE payment.transactions SET status='VALIDATED' WHERE id='$TX4'" >/dev/null
eq payment_app "STM aller" "EXECUTED" "SELECT status FROM payment.fn_execute_transaction('$TX4')"

echo "== Moteur de remédiation : garde de clôture =="
FPI=$(printf 'b%.0s' {1..64})
INC=$(q remediation_app "INSERT INTO remediation.incidents (fingerprint, category, severity, title, target_service, playbook_code) VALUES ('$FPI','DATA_INTEGRITY_VIOLATION','CRITICAL','Divergence soldes','payment-api','PB-INTEGRITY-RESTORE') RETURNING id")
ko remediation_app "doublon d'incident ouvert" "uq_incidents_open_fingerprint" "INSERT INTO remediation.incidents (fingerprint, category, severity, title, target_service) VALUES ('$FPI','DATA_INTEGRITY_VIOLATION','CRITICAL','x','payment-api')"
ok remediation_app "OPEN->TRIAGED->REMEDIATING->VERIFYING" "UPDATE remediation.incidents SET status='TRIAGED', status_reason='playbook selected' WHERE id='$INC'; UPDATE remediation.incidents SET status='REMEDIATING', status_reason='attempt 1' WHERE id='$INC'; UPDATE remediation.incidents SET status='VERIFYING', status_reason='steps ok' WHERE id='$INC'; SELECT status FROM remediation.incidents WHERE id='$INC'"
ko remediation_app "clôture SANS vérification" "last synthetic verification is missing" "UPDATE remediation.incidents SET status='RESOLVED' WHERE id='$INC'"
RUN=$(q remediation_app "INSERT INTO remediation.verification_runs (incident_id, trigger_source) VALUES ('$INC','REMEDIATION') RETURNING id")
q remediation_app "UPDATE remediation.verification_runs SET status='FAILED', failed_check='SYNTHETIC_TX_EXECUTE', finished_at=clock_timestamp() WHERE id='$RUN'" >/dev/null
ko remediation_app "clôture après vérification FAILED" "is FAILED" "UPDATE remediation.incidents SET status='RESOLVED' WHERE id='$INC'"
RUN2=$(q remediation_app "INSERT INTO remediation.verification_runs (incident_id, trigger_source) VALUES ('$INC','REMEDIATION') RETURNING id")
q remediation_app "UPDATE remediation.verification_runs SET status='PASSED', finished_at=clock_timestamp() WHERE id='$RUN2'" >/dev/null
eq remediation_app "clôture après vérification PASSED" "RESOLVED|AUTOMATIC|true" "UPDATE remediation.incidents SET status='RESOLVED', status_reason='synthetic verification passed' WHERE id='$INC' RETURNING status||'|'||resolution||'|'||(verified_at IS NOT NULL)"
eq remediation_app "chronologie complète" "OPEN>TRIAGED>REMEDIATING>VERIFYING>RESOLVED" "SELECT string_agg(to_status::text,'>' ORDER BY id) FROM remediation.incident_transitions WHERE incident_id='$INC'"
ko remediation_app "incident clos immuable" "immutable" "UPDATE remediation.incidents SET title='x' WHERE id='$INC'"

echo
if [ $FAIL -eq 0 ]; then echo "RESULTAT: TOUS LES TESTS PASSENT"; else echo "RESULTAT: ECHECS"; exit 1; fi
