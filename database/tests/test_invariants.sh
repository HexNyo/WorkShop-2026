#!/usr/bin/env bash
# =============================================================================
# PROJECT RESILIENCE-ALPHA — tests d'acceptation du socle de données (MariaDB)
# Usage : scripts/test-database.sh (base éphémère, CHAOS_LAB_ENABLED=true).
# Ne jamais exécuter sur une base contenant des données à conserver.
# =============================================================================
set -uo pipefail
FAIL=0
pw()  {
  case "$1" in
    ra_auth_app)        printf '%s' "$RA_DB_AUTH_PASSWORD" ;;
    ra_payment_app)     printf '%s' "$RA_DB_PAYMENT_PASSWORD" ;;
    ra_payment_maint)   printf '%s' "$RA_DB_PAYMENT_MAINT_PASSWORD" ;;
    ra_remediation_app) printf '%s' "$RA_DB_REMEDIATION_PASSWORD" ;;
    root)               printf '%s' "$MARIADB_ROOT_PASSWORD" ;;
  esac
}
# Comptes applicatifs en TCP ; root par le socket local.
q()   {
  local host=(--host=127.0.0.1); [ "$1" = root ] && host=()
  MYSQL_PWD="$(pw "$1")" mariadb "${host[@]}" --user="$1" --batch --skip-column-names -e "$2" 2>&1
}
last() { q "$1" "$2" | tail -n1; }   # dernière ligne (ex. SELECT de contrôle après un CALL)
ok()  { local out; out=$(q "$1" "$3"); if [ $? -eq 0 ]; then echo "PASS  $2 -> ${out//$'\n'/ | }"; else echo "FAIL  $2 -> $out"; FAIL=1; fi; }
ko()  { local out; out=$(q "$1" "$4"); if [ $? -ne 0 ] && grep -q "$3" <<<"$out"; then echo "PASS  $2 (refusé: $3)"; else echo "FAIL  $2 -> attendu '$3', obtenu: $out"; FAIL=1; fi; }
check() { if [ "$3" == "$2" ]; then echo "PASS  $1 = $2"; else echo "FAIL  $1 -> attendu '$2', obtenu '$3'"; FAIL=1; fi; }
eq()  { check "$2" "$3" "$(q "$1" "$4")"; }
# Résultat d'exécution : CALL puis relecture de l'état (le CALL renvoie la ligne complète).
exec_tx() { last ra_payment_app "CALL ra_payment.sp_execute_transaction('$1'); SELECT CONCAT_WS('|', status, failure_code) FROM ra_payment.transactions WHERE id='$1'"; }
# Rapport d'intégrité : colonnes check_code, severity, passed, violations, sample.
report() { q ra_payment_app "CALL ra_payment.sp_integrity_report(300)"; }
critical_ok() { report | awk -F'\t' '$2 == "CRITICAL" && $3 != 1 { bad = 1 } END { print bad ? "f" : "t" }'; }
failed_checks() { report | awk -F'\t' '$3 != 1 { print $1 }' | sort | paste -sd, -; }

ALICE=10000000-0000-4000-8000-000000000001
BOB=10000000-0000-4000-8000-000000000003
BOBUSD=10000000-0000-4000-8000-000000000004
SYNA=90000000-0000-4000-8000-000000000001
SYNB=90000000-0000-4000-8000-000000000002
PALICE=00000000-0000-4000-8000-000000000002
FP="UNHEX(REPEAT('aa', 32))"
TXCOLS="initiator_principal_id, idempotency_key, request_fingerprint, debit_account_id, credit_account_id, amount_minor, currency"

echo "== Authentification réseau =="
out=$(q ra_payment_app 'SELECT CURRENT_USER()')
if [[ "$out" == ra_payment_app@* ]]; then echo "PASS  compte applicatif accepté en TCP"; else echo "FAIL  compte applicatif TCP -> $out"; FAIL=1; fi
out=$(MYSQL_PWD="mauvais-mot-de-passe" mariadb --host=127.0.0.1 --user=ra_payment_app --batch -e 'SELECT 1' 2>&1)
if grep -q "Access denied" <<<"$out"; then echo "PASS  mauvais mot de passe refusé"; else echo "FAIL  mauvais mot de passe -> $out"; FAIL=1; fi
out=$(MYSQL_PWD="x" mariadb --host=127.0.0.1 --user=ra_owner --batch -e 'SELECT 1' 2>&1)
if grep -q "locked\|Access denied" <<<"$out"; then echo "PASS  propriétaire des objets non connectable"; else echo "FAIL  ra_owner -> $out"; FAIL=1; fi

echo "== Paiement nominal =="
TX=$(q ra_payment_app "INSERT INTO ra_payment.transactions ($TXCOLS) VALUES ('$PALICE','idem-0001-test',$FP,'$ALICE','$BOB',12550,'EUR') RETURNING id")
echo "tx=$TX"
eq ra_payment_app "validation PENDING->VALIDATED" "VALIDATED" "UPDATE ra_payment.transactions SET status='VALIDATED' WHERE id='$TX'; SELECT status FROM ra_payment.transactions WHERE id='$TX'"
check "exécution atomique" "EXECUTED" "$(exec_tx "$TX")"
check "ré-exécution idempotente" "EXECUTED" "$(exec_tx "$TX")"
eq ra_payment_app "solde Alice" "487450" "SELECT available_minor FROM ra_payment.account_balances WHERE account_id='$ALICE'"
eq ra_payment_app "solde Bob" "262550" "SELECT available_minor FROM ra_payment.account_balances WHERE account_id='$BOB'"
eq ra_payment_app "historique d'états" "PENDING>VALIDATED>EXECUTED" "SELECT GROUP_CONCAT(to_status ORDER BY id SEPARATOR '>') FROM ra_payment.transaction_status_history WHERE transaction_id='$TX'"

echo "== Refus et garde-fous =="
ko ra_payment_app "clé d'idempotence dupliquée" "uq_transactions_idempotency" "INSERT INTO ra_payment.transactions ($TXCOLS) VALUES ('$PALICE','idem-0001-test',$FP,'$ALICE','$BOB',1,'EUR')"
ok ra_payment_app "clé d'idempotence sensible à la casse" "INSERT INTO ra_payment.transactions ($TXCOLS) VALUES ('$PALICE','IDEM-0001-TEST',$FP,'$ALICE','$BOB',1,'EUR')"
ko ra_payment_app "devise incohérente" "currency mismatch" "INSERT INTO ra_payment.transactions ($TXCOLS) VALUES ('$PALICE','idem-0002-test',$FP,'$ALICE','$BOBUSD',1,'EUR')"
ko ra_payment_app "ségrégation synthétique" "synthetic transactions" "INSERT INTO ra_payment.transactions ($TXCOLS, is_synthetic) VALUES ('$PALICE','idem-0003-test',$FP,'$ALICE','$SYNA',1,'EUR',true)"
TX2=$(q ra_payment_app "INSERT INTO ra_payment.transactions ($TXCOLS) VALUES ('$PALICE','idem-0004-test',$FP,'$BOB','$ALICE',99999999,'EUR') RETURNING id")
q ra_payment_app "UPDATE ra_payment.transactions SET status='VALIDATED' WHERE id='$TX2'" >/dev/null
check "provision insuffisante => REJECTED" "REJECTED|INSUFFICIENT_FUNDS" "$(exec_tx "$TX2")"
ko ra_payment_app "transition depuis état terminal" "illegal transition" "UPDATE ra_payment.transactions SET status='VALIDATED' WHERE id='$TX'"
TX5=$(q ra_payment_app "INSERT INTO ra_payment.transactions ($TXCOLS) VALUES ('$PALICE','idem-0005-test',$FP,'$ALICE','$BOB',1,'EUR') RETURNING id")
q ra_payment_app "UPDATE ra_payment.transactions SET status='VALIDATED' WHERE id='$TX5'" >/dev/null
ko ra_payment_app "EXECUTED sans écritures (contournement)" "cannot be EXECUTED" "UPDATE ra_payment.transactions SET status='EXECUTED' WHERE id='$TX5'"
eq ra_payment_app "annulation VALIDATED->CANCELLED" "CANCELLED" "UPDATE ra_payment.transactions SET status='CANCELLED' WHERE id='$TX5'; SELECT status FROM ra_payment.transactions WHERE id='$TX5'"
ko ra_payment_app "UPDATE direct d'un solde" "command denied" "UPDATE ra_payment.account_balances SET available_minor=0"
ko ra_payment_app "INSERT direct au grand livre" "command denied" "INSERT INTO ra_payment.ledger_entries (transaction_id, account_id, direction, amount_minor, currency) VALUES ('$TX','$ALICE','DEBIT',1,'EUR')"
ko ra_payment_app "modification du montant" "command denied" "UPDATE ra_payment.transactions SET amount_minor=1 WHERE id='$TX'"
ko root "grand livre append-only (même root)" "append-only" "DELETE FROM ra_payment.ledger_entries"
ko ra_payment_app "accès à la base ra_auth" "command denied" "SELECT * FROM ra_auth.principals"
ko ra_remediation_app "accès à la base ra_payment" "command denied" "SELECT * FROM ra_payment.accounts"
ko ra_payment_app "réparation réservée à ra_payment_maint" "command denied" "CALL ra_payment.sp_repair_balances('test reason', NULL, true)"
ko ra_auth_app "rôle de service sur un humain" "cannot be granted" "INSERT INTO ra_auth.principal_roles (principal_id, role_code) VALUES ('$PALICE','svc.detector')"

echo "== Intégrité : état sain =="
check "rapport d'intégrité (contrôles critiques)" "t" "$(critical_ok)"

echo "== Attaque simulée : altération directe d'un solde =="
ok ra_payment_maint "altération (laboratoire)" "CALL ra_payment.sp_lab_tamper_balance('RA-1000-0003', 50000)"
check "contrôles en échec" "BALANCE_MATCHES_LEDGER,MONEY_CONSERVATION" "$(failed_checks)"
TX3=$(q ra_payment_app "INSERT INTO ra_payment.transactions ($TXCOLS) VALUES ('$PALICE','idem-0006-test',$FP,'$ALICE','$BOB',100,'EUR') RETURNING id")
q ra_payment_app "UPDATE ra_payment.transactions SET status='VALIDATED' WHERE id='$TX3'" >/dev/null
ko ra_payment_app "écriture bloquée sur compte altéré" "balance/ledger divergence" "CALL ra_payment.sp_execute_transaction('$TX3')"

echo "== Remédiation : reconstruction depuis le grand livre =="
check "simulation (dry-run)" "available_minor:312550->262550" \
  "$(q ra_payment_maint "CALL ra_payment.sp_repair_balances('incident test', NULL, true)" | awk -F'\t' '{ print $2 ":" $3 "->" $4 }' | paste -sd, -)"
ok ra_payment_maint "réparation" "CALL ra_payment.sp_repair_balances('incident test repair', NULL, false)"
check "intégrité rétablie" "t" "$(critical_ok)"
check "transaction de nouveau possible" "EXECUTED" "$(exec_tx "$TX3")"
eq ra_payment_maint "purge des transactions en vol (seuil 60s)" "0" "CALL ra_payment.sp_fail_stale_transactions(60, 'purge test', NULL)"
ko ra_payment_maint "purge : seuil minimal" "must be >= 60" "CALL ra_payment.sp_fail_stale_transactions(10, 'purge test', NULL)"
eq ra_payment_maint "bascule quarantaine synthétique" "\"SYNTHETIC_ONLY\"" "UPDATE ra_payment.runtime_flags SET value='\"SYNTHETIC_ONLY\"', reason='test' WHERE \`key\`='write_mode'; SELECT value FROM ra_payment.runtime_flags WHERE \`key\`='write_mode'"
ko ra_payment_maint "write_mode invalide" "ck_flags_value" "UPDATE ra_payment.runtime_flags SET value='\"OPEN_BAR\"', reason='test' WHERE \`key\`='write_mode'"
eq ra_payment_maint "journal des changements de flag" "\"READ_WRITE\">\"SYNTHETIC_ONLY\"" "SELECT CONCAT(old_value, '>', new_value) FROM ra_payment.runtime_flag_changes WHERE \`key\`='write_mode' AND old_value IS NOT NULL"

echo "== Transaction synthétique =="
PSYN=00000000-0000-4000-8000-000000000102
TX4=$(q ra_payment_app "INSERT INTO ra_payment.transactions ($TXCOLS, is_synthetic) VALUES ('$PSYN','synthetic-run1-fwd',$FP,'$SYNA','$SYNB',1,'EUR',true) RETURNING id")
q ra_payment_app "UPDATE ra_payment.transactions SET status='VALIDATED' WHERE id='$TX4'" >/dev/null
check "STM aller" "EXECUTED" "$(exec_tx "$TX4")"

echo "== Moteur de remédiation : garde de clôture =="
FPI=$(printf 'b%.0s' {1..64})
INC=$(q ra_remediation_app "INSERT INTO ra_remediation.incidents (fingerprint, category, severity, title, target_service, playbook_code) VALUES ('$FPI','DATA_INTEGRITY_VIOLATION','CRITICAL','Divergence soldes','payment-api','PB-INTEGRITY-RESTORE') RETURNING id")
ko ra_remediation_app "doublon d'incident ouvert" "uq_incidents_open_fingerprint" "INSERT INTO ra_remediation.incidents (fingerprint, category, severity, title, target_service) VALUES ('$FPI','DATA_INTEGRITY_VIOLATION','CRITICAL','x','payment-api')"
eq ra_remediation_app "OPEN->TRIAGED->REMEDIATING->VERIFYING" "VERIFYING" "UPDATE ra_remediation.incidents SET status='TRIAGED', status_reason='playbook selected' WHERE id='$INC'; UPDATE ra_remediation.incidents SET status='REMEDIATING', status_reason='attempt 1' WHERE id='$INC'; UPDATE ra_remediation.incidents SET status='VERIFYING', status_reason='steps ok' WHERE id='$INC'; SELECT status FROM ra_remediation.incidents WHERE id='$INC'"
ko ra_remediation_app "clôture SANS vérification" "last synthetic verification is missing" "UPDATE ra_remediation.incidents SET status='RESOLVED' WHERE id='$INC'"
RUN=$(q ra_remediation_app "INSERT INTO ra_remediation.verification_runs (incident_id, trigger_source) VALUES ('$INC','REMEDIATION') RETURNING id")
q ra_remediation_app "UPDATE ra_remediation.verification_runs SET status='FAILED', failed_check='SYNTHETIC_TX_EXECUTE', finished_at=SYSDATE(6) WHERE id='$RUN'" >/dev/null
ko ra_remediation_app "clôture après vérification FAILED" "is FAILED" "UPDATE ra_remediation.incidents SET status='RESOLVED' WHERE id='$INC'"
RUN2=$(q ra_remediation_app "INSERT INTO ra_remediation.verification_runs (incident_id, trigger_source) VALUES ('$INC','REMEDIATION') RETURNING id")
q ra_remediation_app "UPDATE ra_remediation.verification_runs SET status='PASSED', finished_at=SYSDATE(6) WHERE id='$RUN2'" >/dev/null
eq ra_remediation_app "clôture après vérification PASSED" "RESOLVED|AUTOMATIC|true" "UPDATE ra_remediation.incidents SET status='RESOLVED', status_reason='synthetic verification passed' WHERE id='$INC'; SELECT CONCAT_WS('|', status, resolution, IF(verified_at IS NOT NULL, 'true', 'false')) FROM ra_remediation.incidents WHERE id='$INC'"
eq ra_remediation_app "chronologie complète" "OPEN>TRIAGED>REMEDIATING>VERIFYING>RESOLVED" "SELECT GROUP_CONCAT(to_status ORDER BY id SEPARATOR '>') FROM ra_remediation.incident_transitions WHERE incident_id='$INC'"
ko ra_remediation_app "incident clos immuable" "immutable" "UPDATE ra_remediation.incidents SET title='x' WHERE id='$INC'"
ok ra_remediation_app "nouvel incident après clôture (même empreinte)" "INSERT INTO ra_remediation.incidents (fingerprint, category, severity, title, target_service) VALUES ('$FPI','DATA_INTEGRITY_VIOLATION','CRITICAL','récidive','payment-api') RETURNING status"
ko root "un seul playbook actif par catégorie" "uq_playbooks_active_category" "INSERT INTO ra_remediation.playbooks (code, category, title, description, steps) VALUES ('PB-DUPLICATE', 'SERVICE_UNAVAILABLE', 't', 'd', '[{\"action\": \"probe.wait_ready\"}]')"

echo
if [ $FAIL -eq 0 ]; then echo "RESULTAT: TOUS LES TESTS PASSENT"; else echo "RESULTAT: ECHECS"; exit 1; fi
