# 02 — Modèle de données (MCD / MPD)

> Implémentation de référence : [database/init/](../database/init/) — PostgreSQL 17.
> Validée par la suite [database/tests/test_invariants.sh](../database/tests/test_invariants.sh) (43 assertions, via [scripts/test-database.sh](../scripts/test-database.sh)).

## 1. Principes

1. **Une base, trois schémas, trois propriétaires fonctionnels** — `auth`, `payment`, `remediation`. Aucun service ne lit le schéma d'un autre : les interactions passent exclusivement par les API. Les références inter-domaines (`owner_principal_id`, `incident_id`…) sont **logiques** (UUID sans FK) pour préserver le découplage et permettre une scission future en bases distinctes.
2. **La base est la dernière ligne de défense** : les invariants financiers et le critère de clôture d'incident sont garantis par contraintes et déclencheurs, même si le code applicatif est défaillant ou compromis.
3. **Append-only par défaut** pour tout ce qui relève de la preuve (grand livre, historiques, audit) — y compris contre le propriétaire et le superutilisateur (hors désactivation explicite des triggers).
4. **Montants en `bigint` d'unités mineures**, jamais de type flottant.

## 2. MCD — schéma `auth`

```mermaid
erDiagram
    ROLES ||--o{ PRINCIPAL_ROLES : "attribué via"
    PRINCIPALS ||--o{ PRINCIPAL_ROLES : "possède"
    PRINCIPALS ||--o{ REFRESH_TOKENS : "détient"
    PRINCIPALS ||--o{ REVOCATION_EVENTS : "fait l'objet de"

    ROLES {
        varchar code PK "ex. payment.customer"
        text description
        enum applies_to "USER | SERVICE"
        bool is_privileged
    }
    PRINCIPALS {
        uuid id PK
        enum kind "USER | SERVICE"
        varchar username UK
        text secret_hash "Argon2id ou '!'"
        bool is_active
        int failed_login_count
        timestamptz locked_until
        timestamptz tokens_valid_after
    }
    PRINCIPAL_ROLES {
        uuid principal_id PK,FK
        varchar role_code PK,FK
        uuid granted_by FK
    }
    REFRESH_TOKENS {
        uuid id PK
        uuid family_id
        uuid principal_id FK
        bytea token_hash UK "SHA-256"
        timestamptz expires_at
        timestamptz used_at
        timestamptz revoked_at
    }
    REVOCATION_EVENTS {
        bigint seq PK "curseur de synchro"
        enum kind "JTI | PRINCIPAL"
        uuid jti
        uuid principal_id FK
        timestamptz not_before
        timestamptz expires_at "horizon de purge"
    }
    AUDIT_EVENTS {
        bigint id PK
        varchar event_type
        varchar outcome
        uuid principal_id
        jsonb details
    }
```

## 3. MCD — schéma `payment`

```mermaid
erDiagram
    CURRENCIES ||--o{ ACCOUNTS : "libelle"
    ACCOUNTS ||--|| ACCOUNT_BALANCES : "projette"
    ACCOUNTS ||--o{ TRANSACTIONS : "débité par"
    ACCOUNTS ||--o{ TRANSACTIONS : "crédité par"
    TRANSACTIONS ||--o{ TRANSACTION_STATUS_HISTORY : "historise"
    TRANSACTIONS ||--o{ LEDGER_ENTRIES : "0 ou 2 écritures"
    ACCOUNTS ||--o{ LEDGER_ENTRIES : "chaîne de hachage"
    ACCOUNTS ||--o{ INTEGRITY_REPAIRS : "corrigé par"
    RUNTIME_FLAGS ||--o{ RUNTIME_FLAG_CHANGES : "audité par"

    ACCOUNTS {
        uuid id PK
        varchar account_number UK "RA-NNNN-NNNN"
        uuid owner_principal_id "réf. logique auth"
        char currency FK
        enum status "ACTIVE | FROZEN | CLOSED"
        bool is_synthetic "RA-9xxx"
        bigint opening_balance_minor
    }
    ACCOUNT_BALANCES {
        uuid account_id PK,FK
        bigint available_minor ">= 0"
        bigint entry_count
        bytea last_entry_hash
        bigint version
    }
    TRANSACTIONS {
        uuid id PK
        uuid initiator_principal_id
        varchar idempotency_key "UK avec initiateur"
        bytea request_fingerprint
        uuid debit_account_id FK
        uuid credit_account_id FK
        bigint amount_minor
        enum status
        varchar failure_code
        bool is_synthetic
        varchar correlation_id
    }
    LEDGER_ENTRIES {
        bigint id PK
        uuid transaction_id FK
        uuid account_id FK
        enum direction "DEBIT | CREDIT"
        bigint amount_minor
        bigint account_seq "UK avec compte"
        bigint balance_after_minor
        bytea prev_hash
        bytea entry_hash
    }
    TRANSACTION_STATUS_HISTORY {
        bigint id PK
        uuid transaction_id FK
        enum from_status
        enum to_status
        timestamptz changed_at
    }
    RUNTIME_FLAGS {
        varchar key PK
        jsonb value
        varchar reason
        uuid incident_id
    }
    INTEGRITY_REPORTS {
        uuid id PK
        varchar trigger_source
        bool passed
        int critical_failures
        jsonb checks
    }
```

### 3.1 Machine à états d'une transaction

```mermaid
stateDiagram-v2
    [*] --> PENDING : POST /v1/transactions
    PENDING --> VALIDATED : contrôles métier OK
    PENDING --> REJECTED : contrôle métier KO
    PENDING --> CANCELLED : annulation
    PENDING --> FAILED : erreur technique / purge STALE_PURGED
    VALIDATED --> EXECUTED : fn_execute_transaction (2 écritures)
    VALIDATED --> REJECTED : provision insuffisante / compte gelé
    VALIDATED --> CANCELLED : annulation
    VALIDATED --> FAILED : divergence RA009 / purge
    EXECUTED --> [*]
    REJECTED --> [*]
    CANCELLED --> [*]
    FAILED --> [*]
```

Toute autre transition est refusée par la base (SQLSTATE `RA008`). `validated_at` / `executed_at` sont posés exclusivement par les déclencheurs.

### 3.2 Chaîne de hachage du grand livre

Pour chaque compte, l'écriture *n* référence l'empreinte de l'écriture *n-1* :

```
genesis(compte)      = SHA-256("RA-GENESIS|" ‖ account_id)
entry_hash(n)        = SHA-256(prev_hash(n) ‖ "account_id|seq|tx_id|direction|amount|currency|balance_after")
prev_hash(n)         = entry_hash(n-1)   (ou genesis si n = 1)
account_balances     = projection de la dernière écriture (balance_after, seq, entry_hash)
```

Avant toute nouvelle écriture, le déclencheur compare la projection `account_balances` à la queue du grand livre (`v_account_ledger_tail`). Toute divergence (altération directe d'un solde) **bloque l'écriture** avec `RA009` : le système passe en mode *fail-safe* sur le compte concerné, et l'anomalie devient détectable (métrique `ra_ledger_divergence_total`, rapport d'intégrité).

## 4. MCD — schéma `remediation`

```mermaid
erDiagram
    PLAYBOOKS ||--o{ INCIDENTS : "sélectionné pour"
    INCIDENTS ||--o{ ALERTS : "agrège"
    INCIDENTS ||--o{ INCIDENT_TRANSITIONS : "chronologie"
    INCIDENTS ||--o{ EXECUTIONS : "tentatives"
    PLAYBOOKS ||--o{ EXECUTIONS : "version exécutée"
    EXECUTIONS ||--o{ EXECUTION_STEPS : "étapes"
    INCIDENTS ||--o{ VERIFICATION_RUNS : "preuves de reprise"
    EXECUTIONS ||--o{ VERIFICATION_RUNS : "valide"
    VERIFICATION_RUNS ||--o{ VERIFICATION_CHECKS : "contrôles"
    INCIDENTS ||--o{ PHASE_HISTORY : "provoque"

    PLAYBOOKS {
        varchar code PK "PB-…"
        int version
        enum category "UK si enabled"
        jsonb steps
        jsonb post_verification_steps
        smallint max_attempts
        int cooldown_seconds
        bool enabled
    }
    INCIDENTS {
        uuid id PK
        char fingerprint "UK si ouvert"
        enum category
        enum severity
        enum status
        varchar status_reason
        service target_service
        uuid target_principal_id
        uuid target_account_id
        smallint attempt_count
        timestamptz verified_at "obligatoire si RESOLVED"
    }
    ALERTS {
        uuid id PK
        varchar source "UK avec external_id"
        varchar external_id
        char fingerprint
        jsonb payload
        uuid incident_id FK
    }
    EXECUTIONS {
        uuid id PK
        uuid incident_id FK
        smallint attempt "UK avec incident"
        enum status
    }
    EXECUTION_STEPS {
        bigint id PK
        uuid execution_id FK
        varchar phase "REMEDIATION | POST_VERIFICATION"
        smallint seq
        varchar action "ex. docker.restart_container"
        enum status
        jsonb output
    }
    VERIFICATION_RUNS {
        uuid id PK
        uuid incident_id FK
        enum status "RUNNING | PASSED | FAILED"
        varchar failed_check
        uuid_array synthetic_transaction_ids
    }
    VERIFICATION_CHECKS {
        bigint id PK
        uuid run_id FK
        varchar check_code
        bool passed
        int latency_ms
    }
    SERVICE_HEALTH_SAMPLES {
        bigint id PK
        service service
        enum status "UP | DEGRADED | DOWN | UNKNOWN"
        int latency_ms
        timestamptz observed_at
    }
    PHASE_HISTORY {
        bigint id PK
        enum phase
        timestamptz entered_at
        uuid incident_id FK
    }
```

## 5. MPD — invariants implémentés

| # | Invariant | Mécanisme | Erreur |
|---|---|---|---|
| I1 | Un solde ne change que via le grand livre | `payment_app` sans `UPDATE` sur `account_balances` ; mise à jour exclusivement par `fn_ledger_before_insert` (`SECURITY DEFINER`) | `permission denied` |
| I2 | Grand livre append-only | Triggers `BEFORE UPDATE/DELETE/TRUNCATE` | `RA006` |
| I3 | Partie double | `UNIQUE(transaction_id, direction)` + contrainte différée `trg_ledger_double_entry` + contrôle à la transition `EXECUTED` | `RA007` |
| I4 | Détection d'altération | Chaîne SHA-256 par compte ; comparaison projection / queue du grand livre avant écriture | `RA009` |
| I5 | Solde ≥ 0, masse monétaire constante | `CHECK` + contrôle `MONEY_CONSERVATION` | `RA003` |
| I6 | États et champs financiers immuables | Triggers de transition + privilèges par colonne | `RA008`, `RA011` |
| I7 | Ségrégation synthétique | `CHECK (is_synthetic = account_number LIKE 'RA-9%')` + contrôle à l'insertion | `RA010` |
| I8 | Idempotence | `UNIQUE(initiator_principal_id, idempotency_key)` + `request_fingerprint` | `23505` → HTTP 409 si payload différent |
| R1 | **Pas de clôture d'incident sans STM réussi** | `fn_incidents_before_update` : dernière `verification_run` = `PASSED` | `RA203` |
| R2 | Un incident ouvert par empreinte | Index unique partiel | `23505` → déduplication |
| R3 | Une exécution active par incident | Index unique partiel `WHERE status='RUNNING'` | `23505` |
| R4 | Un playbook actif par catégorie | Index unique partiel `WHERE enabled` | `23505` |

## 6. Rapport d'intégrité — `payment.fn_integrity_report()`

| Code | Sévérité | Vérifie |
|---|---|---|
| `LEDGER_HASH_CHAIN` | CRITICAL | Séquence continue et empreintes recalculées identiques pour chaque écriture |
| `LEDGER_RUNNING_BALANCE` | CRITICAL | `balance_after` = solde d'ouverture + Σ mouvements |
| `BALANCE_MATCHES_LEDGER` | CRITICAL | Projection `account_balances` conforme à la queue du grand livre |
| `DOUBLE_ENTRY` | CRITICAL | 1 débit + 1 crédit du montant pour chaque `EXECUTED`, aucune écriture sinon |
| `MONEY_CONSERVATION` | CRITICAL | Σ soldes = Σ soldes d'ouverture, par devise |
| `SYNTHETIC_SEGREGATION` | CRITICAL | Aucune transaction ne mélange comptes réels et synthétiques |
| `STALE_IN_FLIGHT` | WARNING | Transactions `PENDING`/`VALIDATED` plus anciennes que le seuil (défaut 5 min) |

Chaque ligne renvoie `passed`, `violations` et un échantillon JSON (≤ 5 éléments) exploitable par la console.

## 7. Restauration de cohérence post-incident

| Fonction | Rôle autorisé | Effet |
|---|---|---|
| `fn_repair_balances(reason, incident_id, dry_run)` | `payment_maint` | Verrouille les soldes, **refuse** (`RA012`) si `LEDGER_HASH_CHAIN` ou `LEDGER_RUNNING_BALANCE` échoue (grand livre compromis ⇒ restauration de sauvegarde, escalade humaine) ; sinon reconstruit la projection depuis le grand livre et trace chaque correction dans `integrity_repairs` |
| `fn_fail_stale_transactions(older_than, reason, incident_id)` | `payment_maint` | Passe en `FAILED/STALE_PURGED` les transactions bloquées en vol (jamais de suppression) ; seuil minimal 60 s |
| `UPDATE runtime_flags` | `payment_maint` | Reconfiguration à chaud (`write_mode`, plafonds) ; chaque changement est historisé dans `runtime_flag_changes` |
| `fn_lab_tamper_balance(account, delta)` | `payment_maint` | **Laboratoire uniquement** (`CHAOS_LAB_ENABLED=true`) : altère un solde sans écriture pour simuler l'attaque |

## 8. Rôles PostgreSQL

| Rôle | Login | Privilèges |
|---|---|---|
| `ra_owner` | non | Propriétaire de tous les objets ; utilisé seulement par les scripts de migration (`SET ROLE`) |
| `auth_app` | oui | `auth.*` selon besoin, colonnes modifiables limitées, audit en insertion seule |
| `payment_app` | oui | Lecture `payment.*`, `INSERT` transactions, `UPDATE(status, failure_code, failure_reason)`, `EXECUTE fn_execute_transaction / fn_integrity_report` |
| `payment_maint` | oui | Lecture `payment.*`, flags, gel de comptes, fonctions de réparation/purge |
| `remediation_app` | oui | `remediation.*` (colonnes modifiables limitées), aucun accès `auth`/`payment` |

Chaque rôle a des garde-fous de session (`statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`, `CONNECTION LIMIT`). Les mots de passe sont injectés au premier démarrage par `\getenv`, chiffrés en SCRAM-SHA-256.
