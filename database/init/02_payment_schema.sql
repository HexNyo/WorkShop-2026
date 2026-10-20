-- =============================================================================
-- PROJECT RESILIENCE-ALPHA — 02 : schéma `payment` (propriété fonctionnelle : payment-api)
-- -----------------------------------------------------------------------------
-- Données 100 % fictives. Montants en unités mineures (bigint), jamais en float.
--
-- Invariants garantis PAR LA BASE (défense en profondeur, indépendamment du code) :
--   I1  Un solde ne change QUE par l'écriture d'une ligne de grand livre.
--   I2  Le grand livre est append-only (ni UPDATE, ni DELETE, ni TRUNCATE).
--   I3  Partie double : une transaction EXECUTED a exactement 1 débit et 1 crédit
--       du même montant ; une transaction non EXECUTED n'a aucune écriture.
--   I4  Chaque compte porte une chaîne de hachage SHA-256 de ses écritures
--       (détection d'altération) ; une divergence solde/grand livre bloque l'écriture.
--   I5  Aucun solde négatif ; masse monétaire constante par devise.
--   I6  Machine à états des transactions stricte ; champs financiers immuables.
--   I7  Ségrégation des transactions synthétiques (comptes RA-9xxx uniquement).
--
-- Codes SQLSTATE applicatifs (classe RA0xx) :
--   RA001 transaction introuvable      RA007 violation partie double
--   RA002 état invalide                RA008 transition interdite
--   RA003 provision insuffisante       RA009 divergence solde / grand livre
--   RA004 compte inactif               RA010 violation ségrégation synthétique
--   RA005 devise incohérente           RA011 champ immuable modifié
--   RA006 table append-only            RA012 grand livre compromis (réparation refusée)
-- =============================================================================
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL ROLE ra_owner;

CREATE SCHEMA payment;
REVOKE ALL ON SCHEMA payment FROM PUBLIC;
COMMENT ON SCHEMA payment IS 'Comptes fictifs, transactions, grand livre en partie double (payment-api)';

CREATE TYPE payment.account_status     AS ENUM ('ACTIVE', 'FROZEN', 'CLOSED');
CREATE TYPE payment.transaction_status AS ENUM ('PENDING', 'VALIDATED', 'EXECUTED', 'REJECTED', 'FAILED', 'CANCELLED');
CREATE TYPE payment.entry_direction    AS ENUM ('DEBIT', 'CREDIT');
CREATE TYPE payment.check_severity     AS ENUM ('WARNING', 'CRITICAL');

-- -----------------------------------------------------------------------------
-- Référentiel
-- -----------------------------------------------------------------------------
CREATE TABLE payment.currencies (
    code        char(3)     PRIMARY KEY,
    minor_units smallint    NOT NULL,
    label       varchar(64) NOT NULL,
    CONSTRAINT ck_currency_code  CHECK (code ~ '^[A-Z]{3}$'),
    CONSTRAINT ck_currency_minor CHECK (minor_units BETWEEN 0 AND 4)
);

-- -----------------------------------------------------------------------------
-- Comptes & soldes
-- -----------------------------------------------------------------------------
CREATE TABLE payment.accounts (
    id                    uuid                   PRIMARY KEY DEFAULT gen_random_uuid(),
    account_number        varchar(12)            NOT NULL,
    owner_principal_id    uuid                   NOT NULL,
    holder_name           varchar(128)           NOT NULL,
    currency              char(3)                NOT NULL REFERENCES payment.currencies(code),
    status                payment.account_status NOT NULL DEFAULT 'ACTIVE',
    is_synthetic          boolean                NOT NULL DEFAULT false,
    opening_balance_minor bigint                 NOT NULL DEFAULT 0,
    created_at            timestamptz            NOT NULL DEFAULT now(),
    updated_at            timestamptz            NOT NULL DEFAULT now(),
    CONSTRAINT uq_accounts_number UNIQUE (account_number),
    CONSTRAINT ck_accounts_number_format CHECK (account_number ~ '^RA-[0-9]{4}-[0-9]{4}$'),
    CONSTRAINT ck_accounts_opening CHECK (opening_balance_minor >= 0),
    CONSTRAINT ck_accounts_synthetic_range CHECK (is_synthetic = (account_number LIKE 'RA-9%'))
);
CREATE INDEX ix_accounts_owner ON payment.accounts (owner_principal_id);
COMMENT ON COLUMN payment.accounts.owner_principal_id IS 'Référence logique vers auth.principals.id (pas de FK inter-schéma : découplage des services)';
COMMENT ON COLUMN payment.accounts.account_number IS 'Identifiant fictif RA-NNNN-NNNN (aucun IBAN réel). Plage RA-9xxx réservée au monitoring synthétique';

CREATE TABLE payment.account_balances (
    account_id      uuid        PRIMARY KEY REFERENCES payment.accounts(id) ON DELETE RESTRICT,
    available_minor bigint      NOT NULL,
    entry_count     bigint      NOT NULL DEFAULT 0,
    last_entry_hash bytea       NOT NULL,
    version         bigint      NOT NULL DEFAULT 0,
    updated_at      timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT ck_balance_non_negative CHECK (available_minor >= 0),
    CONSTRAINT ck_balance_entry_count  CHECK (entry_count >= 0),
    CONSTRAINT ck_balance_hash_len     CHECK (octet_length(last_entry_hash) = 32)
);
COMMENT ON TABLE payment.account_balances IS 'Projection matérialisée du grand livre ; jamais modifiable directement par payment_app';

-- -----------------------------------------------------------------------------
-- Transactions & historique
-- -----------------------------------------------------------------------------
CREATE TABLE payment.transactions (
    id                     uuid                       PRIMARY KEY DEFAULT gen_random_uuid(),
    initiator_principal_id uuid                       NOT NULL,
    idempotency_key        varchar(64)                NOT NULL,
    request_fingerprint    bytea                      NOT NULL,
    debit_account_id       uuid                       NOT NULL REFERENCES payment.accounts(id),
    credit_account_id      uuid                       NOT NULL REFERENCES payment.accounts(id),
    amount_minor           bigint                     NOT NULL,
    currency               char(3)                    NOT NULL REFERENCES payment.currencies(code),
    description            varchar(140),
    status                 payment.transaction_status NOT NULL DEFAULT 'PENDING',
    failure_code           varchar(64),
    failure_reason         varchar(512),
    is_synthetic           boolean                    NOT NULL DEFAULT false,
    correlation_id         varchar(64),
    created_at             timestamptz                NOT NULL DEFAULT clock_timestamp(),
    validated_at           timestamptz,
    executed_at            timestamptz,
    updated_at             timestamptz                NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_transactions_idempotency UNIQUE (initiator_principal_id, idempotency_key),
    CONSTRAINT ck_tx_idempotency_key  CHECK (idempotency_key ~ '^[A-Za-z0-9_:.-]{8,64}$'),
    CONSTRAINT ck_tx_fingerprint_len  CHECK (octet_length(request_fingerprint) = 32),
    CONSTRAINT ck_tx_distinct_accounts CHECK (debit_account_id <> credit_account_id),
    CONSTRAINT ck_tx_amount           CHECK (amount_minor > 0 AND amount_minor <= 100000000000),
    CONSTRAINT ck_tx_failure          CHECK ((status IN ('REJECTED', 'FAILED')) = (failure_code IS NOT NULL)),
    CONSTRAINT ck_tx_failure_code     CHECK (failure_code IS NULL OR failure_code ~ '^[A-Z][A-Z_]+$'),
    CONSTRAINT ck_tx_validated_at     CHECK (status NOT IN ('VALIDATED', 'EXECUTED') OR validated_at IS NOT NULL),
    CONSTRAINT ck_tx_executed_at      CHECK ((status = 'EXECUTED') = (executed_at IS NOT NULL))
);
CREATE INDEX ix_tx_created           ON payment.transactions (created_at DESC, id DESC);
CREATE INDEX ix_tx_debit_created     ON payment.transactions (debit_account_id, created_at DESC);
CREATE INDEX ix_tx_credit_created    ON payment.transactions (credit_account_id, created_at DESC);
CREATE INDEX ix_tx_initiator_created ON payment.transactions (initiator_principal_id, created_at DESC);
CREATE INDEX ix_tx_in_flight         ON payment.transactions (created_at) WHERE status IN ('PENDING', 'VALIDATED');
COMMENT ON COLUMN payment.transactions.request_fingerprint IS 'SHA-256 du payload canonique : même clé + payload différent => 409';

CREATE TABLE payment.transaction_status_history (
    id             bigint                     GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    transaction_id uuid                       NOT NULL REFERENCES payment.transactions(id),
    from_status    payment.transaction_status,
    to_status      payment.transaction_status NOT NULL,
    failure_code   varchar(64),
    changed_at     timestamptz                NOT NULL DEFAULT clock_timestamp(),
    db_user        name                       NOT NULL DEFAULT session_user
);
CREATE INDEX ix_tx_history_tx ON payment.transaction_status_history (transaction_id, id);

-- -----------------------------------------------------------------------------
-- Grand livre en partie double, chaîné par compte
-- -----------------------------------------------------------------------------
CREATE TABLE payment.ledger_entries (
    id                  bigint                  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    transaction_id      uuid                    NOT NULL REFERENCES payment.transactions(id),
    account_id          uuid                    NOT NULL REFERENCES payment.accounts(id),
    direction           payment.entry_direction NOT NULL,
    amount_minor        bigint                  NOT NULL,
    currency            char(3)                 NOT NULL REFERENCES payment.currencies(code),
    account_seq         bigint                  NOT NULL,
    balance_after_minor bigint                  NOT NULL,
    prev_hash           bytea                   NOT NULL,
    entry_hash          bytea                   NOT NULL,
    created_at          timestamptz             NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_ledger_account_seq  UNIQUE (account_id, account_seq),
    CONSTRAINT uq_ledger_tx_direction UNIQUE (transaction_id, direction),
    CONSTRAINT ck_ledger_amount  CHECK (amount_minor > 0),
    CONSTRAINT ck_ledger_seq     CHECK (account_seq > 0),
    CONSTRAINT ck_ledger_balance CHECK (balance_after_minor >= 0),
    CONSTRAINT ck_ledger_hash_len CHECK (octet_length(prev_hash) = 32 AND octet_length(entry_hash) = 32)
);
COMMENT ON COLUMN payment.ledger_entries.entry_hash IS 'SHA-256(prev_hash || account|seq|tx|direction|amount|currency|balance_after)';

-- -----------------------------------------------------------------------------
-- Configuration dynamique (reconfiguration à chaud par le moteur de remédiation)
-- -----------------------------------------------------------------------------
CREATE TABLE payment.runtime_flags (
    key         varchar(64)  PRIMARY KEY,
    value       jsonb        NOT NULL,
    reason      varchar(256) NOT NULL,
    updated_by  uuid,
    incident_id uuid,
    updated_at  timestamptz  NOT NULL DEFAULT now(),
    CONSTRAINT ck_flags_key CHECK (key IN ('write_mode', 'max_transaction_amount_minor', 'max_requests_per_minute_per_principal')),
    CONSTRAINT ck_flags_value CHECK (
        CASE
            WHEN key = 'write_mode' THEN (value #>> '{}') IN ('READ_WRITE', 'SYNTHETIC_ONLY', 'READ_ONLY')
            ELSE CASE WHEN jsonb_typeof(value) = 'number' THEN (value #>> '{}')::numeric > 0 ELSE false END
        END
    )
);
COMMENT ON COLUMN payment.runtime_flags.value IS 'write_mode : READ_WRITE | SYNTHETIC_ONLY (quarantaine : seul le trafic synthétique passe) | READ_ONLY';

CREATE TABLE payment.runtime_flag_changes (
    id          bigint       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    key         varchar(64)  NOT NULL,
    old_value   jsonb,
    new_value   jsonb        NOT NULL,
    reason      varchar(256) NOT NULL,
    updated_by  uuid,
    incident_id uuid,
    changed_at  timestamptz  NOT NULL DEFAULT clock_timestamp(),
    db_user     name         NOT NULL DEFAULT session_user
);

-- -----------------------------------------------------------------------------
-- Intégrité : rapports et réparations tracées
-- -----------------------------------------------------------------------------
CREATE TABLE payment.integrity_reports (
    id                uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
    generated_at      timestamptz NOT NULL DEFAULT clock_timestamp(),
    trigger_source    varchar(16) NOT NULL,
    passed            boolean     NOT NULL,
    critical_failures integer     NOT NULL,
    warnings          integer     NOT NULL,
    duration_ms       integer     NOT NULL,
    checks            jsonb       NOT NULL,
    incident_id       uuid,
    CONSTRAINT ck_integrity_trigger CHECK (trigger_source IN ('HEALTH_PROBE', 'REMEDIATION', 'SCHEDULED', 'OPERATOR')),
    CONSTRAINT ck_integrity_counts CHECK (critical_failures >= 0 AND warnings >= 0 AND duration_ms >= 0),
    CONSTRAINT ck_integrity_passed CHECK (passed = (critical_failures = 0))
);
CREATE INDEX ix_integrity_reports_generated ON payment.integrity_reports (generated_at DESC);

CREATE TABLE payment.integrity_repairs (
    id              bigint       GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    repaired_at     timestamptz  NOT NULL DEFAULT clock_timestamp(),
    account_id      uuid         NOT NULL REFERENCES payment.accounts(id),
    field_name      varchar(32)  NOT NULL,
    previous_value  text         NOT NULL,
    corrected_value text         NOT NULL,
    reason          varchar(256) NOT NULL,
    incident_id     uuid,
    db_user         name         NOT NULL DEFAULT session_user
);

-- =============================================================================
-- Fonctions utilitaires
-- =============================================================================
CREATE FUNCTION payment.fn_genesis_hash(p_account_id uuid) RETURNS bytea
LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT sha256(convert_to('RA-GENESIS|' || p_account_id::text, 'UTF8'))
$$;

CREATE FUNCTION payment.fn_entry_hash(
    p_prev_hash     bytea,
    p_account_id    uuid,
    p_account_seq   bigint,
    p_tx_id         uuid,
    p_direction     payment.entry_direction,
    p_amount_minor  bigint,
    p_currency      char(3),
    p_balance_after bigint
) RETURNS bytea
LANGUAGE sql IMMUTABLE PARALLEL SAFE SET search_path = pg_catalog AS $$
    SELECT sha256(p_prev_hash || convert_to(concat_ws('|',
        p_account_id::text, p_account_seq::text, p_tx_id::text, p_direction::text,
        p_amount_minor::text, p_currency::text, p_balance_after::text), 'UTF8'))
$$;

-- Dernier état connu de chaque compte d'après le grand livre (source de vérité).
CREATE VIEW payment.v_account_ledger_tail AS
SELECT a.id                                                  AS account_id,
       COALESCE(t.balance_after_minor, a.opening_balance_minor) AS expected_balance_minor,
       COALESCE(t.account_seq, 0)                            AS expected_entry_count,
       COALESCE(t.entry_hash, payment.fn_genesis_hash(a.id)) AS expected_last_hash
FROM payment.accounts a
LEFT JOIN LATERAL (
    SELECT le.balance_after_minor, le.account_seq, le.entry_hash
    FROM payment.ledger_entries le
    WHERE le.account_id = a.id
    ORDER BY le.account_seq DESC
    LIMIT 1
) t ON true;

CREATE FUNCTION payment.fn_forbid_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, payment AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'RA006', MESSAGE = format('%s.%s is append-only', TG_TABLE_SCHEMA, TG_TABLE_NAME);
END $$;

CREATE FUNCTION payment.fn_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, payment AS $$
BEGIN
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;

-- =============================================================================
-- Déclencheurs : comptes
-- =============================================================================
CREATE FUNCTION payment.fn_accounts_after_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
BEGIN
    INSERT INTO payment.account_balances (account_id, available_minor, entry_count, last_entry_hash)
    VALUES (NEW.id, NEW.opening_balance_minor, 0, payment.fn_genesis_hash(NEW.id));
    RETURN NULL;
END $$;

CREATE FUNCTION payment.fn_accounts_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, payment AS $$
BEGIN
    IF (NEW.id, NEW.account_number, NEW.owner_principal_id, NEW.currency, NEW.is_synthetic, NEW.opening_balance_minor, NEW.created_at)
       IS DISTINCT FROM
       (OLD.id, OLD.account_number, OLD.owner_principal_id, OLD.currency, OLD.is_synthetic, OLD.opening_balance_minor, OLD.created_at) THEN
        RAISE EXCEPTION USING ERRCODE = 'RA011', MESSAGE = format('immutable account fields modified on %s', OLD.id);
    END IF;
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;

CREATE TRIGGER trg_accounts_after_insert  AFTER INSERT ON payment.accounts
    FOR EACH ROW EXECUTE FUNCTION payment.fn_accounts_after_insert();
CREATE TRIGGER trg_accounts_before_update BEFORE UPDATE ON payment.accounts
    FOR EACH ROW EXECUTE FUNCTION payment.fn_accounts_before_update();
CREATE TRIGGER trg_account_balances_no_delete BEFORE DELETE ON payment.account_balances
    FOR EACH ROW EXECUTE FUNCTION payment.fn_forbid_mutation();

-- =============================================================================
-- Déclencheurs : transactions (machine à états, immutabilité, historique)
-- =============================================================================
CREATE FUNCTION payment.fn_transactions_before_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, payment AS $$
DECLARE
    v_debit  payment.accounts%ROWTYPE;
    v_credit payment.accounts%ROWTYPE;
BEGIN
    IF NEW.status <> 'PENDING' THEN
        RAISE EXCEPTION USING ERRCODE = 'RA008', MESSAGE = 'a transaction must be created in PENDING status';
    END IF;

    SELECT * INTO v_debit  FROM payment.accounts WHERE id = NEW.debit_account_id;
    SELECT * INTO v_credit FROM payment.accounts WHERE id = NEW.credit_account_id;
    IF v_debit.id IS NOT NULL AND v_credit.id IS NOT NULL THEN
        IF v_debit.currency <> NEW.currency OR v_credit.currency <> NEW.currency THEN
            RAISE EXCEPTION USING ERRCODE = 'RA005',
                MESSAGE = format('currency mismatch: tx=%s debit=%s credit=%s', NEW.currency, v_debit.currency, v_credit.currency);
        END IF;
        IF v_debit.is_synthetic <> NEW.is_synthetic OR v_credit.is_synthetic <> NEW.is_synthetic THEN
            RAISE EXCEPTION USING ERRCODE = 'RA010',
                MESSAGE = 'synthetic transactions must only involve synthetic accounts (and vice versa)';
        END IF;
    END IF;

    NEW.created_at   := clock_timestamp();
    NEW.updated_at   := NEW.created_at;
    NEW.validated_at := NULL;
    NEW.executed_at  := NULL;
    RETURN NEW;
END $$;

CREATE FUNCTION payment.fn_transactions_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, payment AS $$
DECLARE
    v_entries integer;
BEGIN
    IF (NEW.id, NEW.initiator_principal_id, NEW.idempotency_key, NEW.request_fingerprint, NEW.debit_account_id,
        NEW.credit_account_id, NEW.amount_minor, NEW.currency, NEW.description, NEW.is_synthetic, NEW.correlation_id, NEW.created_at)
       IS DISTINCT FROM
       (OLD.id, OLD.initiator_principal_id, OLD.idempotency_key, OLD.request_fingerprint, OLD.debit_account_id,
        OLD.credit_account_id, OLD.amount_minor, OLD.currency, OLD.description, OLD.is_synthetic, OLD.correlation_id, OLD.created_at) THEN
        RAISE EXCEPTION USING ERRCODE = 'RA011', MESSAGE = format('immutable transaction fields modified on %s', OLD.id);
    END IF;

    -- Les horodatages de cycle de vie sont posés exclusivement par la base.
    NEW.validated_at := OLD.validated_at;
    NEW.executed_at  := OLD.executed_at;

    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF NOT (
               (OLD.status = 'PENDING'   AND NEW.status IN ('VALIDATED', 'REJECTED', 'FAILED', 'CANCELLED'))
            OR (OLD.status = 'VALIDATED' AND NEW.status IN ('EXECUTED', 'REJECTED', 'FAILED', 'CANCELLED'))
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'RA008',
                MESSAGE = format('illegal transition %s -> %s for transaction %s', OLD.status, NEW.status, OLD.id);
        END IF;

        IF NEW.status = 'VALIDATED' THEN
            NEW.validated_at := clock_timestamp();
        ELSIF NEW.status = 'EXECUTED' THEN
            SELECT count(*) INTO v_entries FROM payment.ledger_entries WHERE transaction_id = NEW.id;
            IF v_entries <> 2 THEN
                RAISE EXCEPTION USING ERRCODE = 'RA007',
                    MESSAGE = format('transaction %s cannot be EXECUTED with %s ledger entries', NEW.id, v_entries);
            END IF;
            NEW.executed_at := clock_timestamp();
        END IF;
    ELSIF OLD.status IN ('EXECUTED', 'REJECTED', 'FAILED', 'CANCELLED')
          AND (NEW.failure_code, NEW.failure_reason) IS DISTINCT FROM (OLD.failure_code, OLD.failure_reason) THEN
        RAISE EXCEPTION USING ERRCODE = 'RA011', MESSAGE = format('terminal transaction %s is immutable', OLD.id);
    END IF;

    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;

CREATE FUNCTION payment.fn_transactions_history() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO payment.transaction_status_history (transaction_id, from_status, to_status, failure_code)
        VALUES (NEW.id, NULL, NEW.status, NEW.failure_code);
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO payment.transaction_status_history (transaction_id, from_status, to_status, failure_code)
        VALUES (NEW.id, OLD.status, NEW.status, NEW.failure_code);
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_transactions_before_insert BEFORE INSERT ON payment.transactions
    FOR EACH ROW EXECUTE FUNCTION payment.fn_transactions_before_insert();
CREATE TRIGGER trg_transactions_before_update BEFORE UPDATE ON payment.transactions
    FOR EACH ROW EXECUTE FUNCTION payment.fn_transactions_before_update();
CREATE TRIGGER trg_transactions_history AFTER INSERT OR UPDATE OF status ON payment.transactions
    FOR EACH ROW EXECUTE FUNCTION payment.fn_transactions_history();
CREATE TRIGGER trg_transactions_no_delete BEFORE DELETE ON payment.transactions
    FOR EACH ROW EXECUTE FUNCTION payment.fn_forbid_mutation();
CREATE TRIGGER trg_transactions_no_truncate BEFORE TRUNCATE ON payment.transactions
    FOR EACH STATEMENT EXECUTE FUNCTION payment.fn_forbid_mutation();

CREATE TRIGGER trg_tx_history_immutable BEFORE UPDATE OR DELETE ON payment.transaction_status_history
    FOR EACH ROW EXECUTE FUNCTION payment.fn_forbid_mutation();
CREATE TRIGGER trg_tx_history_no_truncate BEFORE TRUNCATE ON payment.transaction_status_history
    FOR EACH STATEMENT EXECUTE FUNCTION payment.fn_forbid_mutation();

-- =============================================================================
-- Déclencheurs : grand livre
-- =============================================================================
CREATE FUNCTION payment.fn_ledger_before_insert() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
DECLARE
    v_tx          payment.transactions%ROWTYPE;
    v_account     payment.accounts%ROWTYPE;
    v_balance     payment.account_balances%ROWTYPE;
    v_tail        payment.v_account_ledger_tail%ROWTYPE;
    v_new_balance bigint;
BEGIN
    SELECT * INTO v_tx FROM payment.transactions WHERE id = NEW.transaction_id;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'RA001', MESSAGE = format('transaction %s not found', NEW.transaction_id);
    END IF;
    IF v_tx.status <> 'VALIDATED' THEN
        RAISE EXCEPTION USING ERRCODE = 'RA002',
            MESSAGE = format('ledger entries require a VALIDATED transaction (%s is %s)', v_tx.id, v_tx.status);
    END IF;
    IF NEW.amount_minor IS DISTINCT FROM v_tx.amount_minor
       OR NEW.currency IS DISTINCT FROM v_tx.currency
       OR (NEW.direction = 'DEBIT'  AND NEW.account_id <> v_tx.debit_account_id)
       OR (NEW.direction = 'CREDIT' AND NEW.account_id <> v_tx.credit_account_id) THEN
        RAISE EXCEPTION USING ERRCODE = 'RA007', MESSAGE = format('ledger entry does not match transaction %s', v_tx.id);
    END IF;

    SELECT * INTO v_account FROM payment.accounts WHERE id = NEW.account_id;
    IF v_account.status <> 'ACTIVE' THEN
        RAISE EXCEPTION USING ERRCODE = 'RA004', MESSAGE = format('account %s is %s', v_account.account_number, v_account.status);
    END IF;

    SELECT * INTO v_balance FROM payment.account_balances WHERE account_id = NEW.account_id FOR UPDATE;
    SELECT * INTO v_tail    FROM payment.v_account_ledger_tail WHERE account_id = NEW.account_id;

    -- I4 : refus d'écrire sur un compte dont le solde a divergé du grand livre (altération détectée).
    IF v_balance.available_minor <> v_tail.expected_balance_minor
       OR v_balance.entry_count  <> v_tail.expected_entry_count
       OR v_balance.last_entry_hash <> v_tail.expected_last_hash THEN
        RAISE EXCEPTION USING ERRCODE = 'RA009',
            MESSAGE = format('balance/ledger divergence on account %s', v_account.account_number),
            DETAIL  = format('balance=%s expected=%s', v_balance.available_minor, v_tail.expected_balance_minor);
    END IF;

    v_new_balance := CASE NEW.direction
                         WHEN 'DEBIT' THEN v_tail.expected_balance_minor - NEW.amount_minor
                         ELSE v_tail.expected_balance_minor + NEW.amount_minor
                     END;
    IF v_new_balance < 0 THEN
        RAISE EXCEPTION USING ERRCODE = 'RA003', MESSAGE = format('insufficient funds on account %s', v_account.account_number);
    END IF;

    NEW.account_seq         := v_tail.expected_entry_count + 1;
    NEW.balance_after_minor := v_new_balance;
    NEW.prev_hash           := v_tail.expected_last_hash;
    NEW.created_at          := clock_timestamp();
    NEW.entry_hash          := payment.fn_entry_hash(NEW.prev_hash, NEW.account_id, NEW.account_seq, NEW.transaction_id,
                                                     NEW.direction, NEW.amount_minor, NEW.currency, NEW.balance_after_minor);

    UPDATE payment.account_balances
       SET available_minor = v_new_balance,
           entry_count     = NEW.account_seq,
           last_entry_hash = NEW.entry_hash,
           version         = version + 1,
           updated_at      = clock_timestamp()
     WHERE account_id = NEW.account_id;

    RETURN NEW;
END $$;

-- I3 : contrôle différé en fin de transaction SQL.
CREATE FUNCTION payment.fn_ledger_double_entry_check() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
DECLARE
    v_status  payment.transaction_status;
    v_amount  bigint;
    v_count   integer;
    v_debits  bigint;
    v_credits bigint;
BEGIN
    SELECT status, amount_minor INTO v_status, v_amount FROM payment.transactions WHERE id = NEW.transaction_id;
    SELECT count(*),
           COALESCE(sum(amount_minor) FILTER (WHERE direction = 'DEBIT'), 0),
           COALESCE(sum(amount_minor) FILTER (WHERE direction = 'CREDIT'), 0)
      INTO v_count, v_debits, v_credits
      FROM payment.ledger_entries
     WHERE transaction_id = NEW.transaction_id;

    IF v_status <> 'EXECUTED' OR v_count <> 2 OR v_debits <> v_amount OR v_credits <> v_amount THEN
        RAISE EXCEPTION USING ERRCODE = 'RA007',
            MESSAGE = format('double-entry violation on transaction %s (status=%s entries=%s D=%s C=%s amount=%s)',
                             NEW.transaction_id, v_status, v_count, v_debits, v_credits, v_amount);
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_ledger_before_insert BEFORE INSERT ON payment.ledger_entries
    FOR EACH ROW EXECUTE FUNCTION payment.fn_ledger_before_insert();
CREATE CONSTRAINT TRIGGER trg_ledger_double_entry AFTER INSERT ON payment.ledger_entries
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION payment.fn_ledger_double_entry_check();
CREATE TRIGGER trg_ledger_immutable BEFORE UPDATE OR DELETE ON payment.ledger_entries
    FOR EACH ROW EXECUTE FUNCTION payment.fn_forbid_mutation();
CREATE TRIGGER trg_ledger_no_truncate BEFORE TRUNCATE ON payment.ledger_entries
    FOR EACH STATEMENT EXECUTE FUNCTION payment.fn_forbid_mutation();

-- =============================================================================
-- Déclencheurs : configuration dynamique (journalisation systématique)
-- =============================================================================
CREATE FUNCTION payment.fn_runtime_flags_audit() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
BEGIN
    INSERT INTO payment.runtime_flag_changes (key, old_value, new_value, reason, updated_by, incident_id)
    VALUES (NEW.key, CASE WHEN TG_OP = 'UPDATE' THEN OLD.value END, NEW.value, NEW.reason, NEW.updated_by, NEW.incident_id);
    RETURN NULL;
END $$;

CREATE TRIGGER trg_runtime_flags_touch BEFORE UPDATE ON payment.runtime_flags
    FOR EACH ROW EXECUTE FUNCTION payment.fn_touch_updated_at();
CREATE TRIGGER trg_runtime_flags_audit AFTER INSERT OR UPDATE ON payment.runtime_flags
    FOR EACH ROW EXECUTE FUNCTION payment.fn_runtime_flags_audit();
CREATE TRIGGER trg_runtime_flag_changes_immutable BEFORE UPDATE OR DELETE ON payment.runtime_flag_changes
    FOR EACH ROW EXECUTE FUNCTION payment.fn_forbid_mutation();
CREATE TRIGGER trg_integrity_repairs_immutable BEFORE UPDATE OR DELETE ON payment.integrity_repairs
    FOR EACH ROW EXECUTE FUNCTION payment.fn_forbid_mutation();

-- =============================================================================
-- Primitive transactionnelle : exécution atomique d'une transaction VALIDATED
-- =============================================================================
-- Idempotente (une transaction déjà EXECUTED est renvoyée telle quelle).
-- Verrouillage ordonné des soldes (par account_id) => aucun interblocage.
-- Les refus métier (compte inactif, provision insuffisante) sont historisés
-- en REJECTED au sein de la même transaction SQL, sans exception.
CREATE FUNCTION payment.fn_execute_transaction(p_transaction_id uuid)
RETURNS payment.transactions
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
DECLARE
    v_tx        payment.transactions%ROWTYPE;
    v_debit     payment.accounts%ROWTYPE;
    v_credit    payment.accounts%ROWTYPE;
    v_available bigint;
BEGIN
    SELECT * INTO v_tx FROM payment.transactions WHERE id = p_transaction_id FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'RA001', MESSAGE = format('transaction %s not found', p_transaction_id);
    END IF;
    IF v_tx.status = 'EXECUTED' THEN
        RETURN v_tx;
    END IF;
    IF v_tx.status <> 'VALIDATED' THEN
        RAISE EXCEPTION USING ERRCODE = 'RA002',
            MESSAGE = format('transaction %s is %s, expected VALIDATED', v_tx.id, v_tx.status);
    END IF;

    PERFORM 1
       FROM payment.account_balances
      WHERE account_id IN (v_tx.debit_account_id, v_tx.credit_account_id)
      ORDER BY account_id
        FOR UPDATE;

    SELECT * INTO v_debit  FROM payment.accounts WHERE id = v_tx.debit_account_id;
    SELECT * INTO v_credit FROM payment.accounts WHERE id = v_tx.credit_account_id;

    IF v_debit.status <> 'ACTIVE' OR v_credit.status <> 'ACTIVE' THEN
        UPDATE payment.transactions
           SET status = 'REJECTED', failure_code = 'ACCOUNT_NOT_ACTIVE',
               failure_reason = format('debit=%s credit=%s', v_debit.status, v_credit.status)
         WHERE id = v_tx.id
        RETURNING * INTO v_tx;
        RETURN v_tx;
    END IF;

    SELECT available_minor INTO v_available FROM payment.account_balances WHERE account_id = v_tx.debit_account_id;
    IF v_available < v_tx.amount_minor THEN
        UPDATE payment.transactions
           SET status = 'REJECTED', failure_code = 'INSUFFICIENT_FUNDS',
               failure_reason = 'available balance lower than requested amount'
         WHERE id = v_tx.id
        RETURNING * INTO v_tx;
        RETURN v_tx;
    END IF;

    INSERT INTO payment.ledger_entries (transaction_id, account_id, direction, amount_minor, currency)
    VALUES (v_tx.id, v_tx.debit_account_id,  'DEBIT',  v_tx.amount_minor, v_tx.currency),
           (v_tx.id, v_tx.credit_account_id, 'CREDIT', v_tx.amount_minor, v_tx.currency);

    UPDATE payment.transactions SET status = 'EXECUTED' WHERE id = v_tx.id
    RETURNING * INTO v_tx;
    RETURN v_tx;
END $$;

-- =============================================================================
-- Rapport d'intégrité (consommé par /health/integrity et par la remédiation)
-- =============================================================================
CREATE FUNCTION payment.fn_integrity_report(p_stale_after interval DEFAULT interval '5 minutes')
RETURNS TABLE (check_code text, severity payment.check_severity, passed boolean, violations bigint, sample jsonb)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
#variable_conflict use_column
BEGIN
    -- C1 : chaîne de hachage et séquence par compte (altération du grand livre).
    RETURN QUERY
    WITH chain AS (
        SELECT le.*,
               row_number() OVER w AS exp_seq,
               lag(le.entry_hash) OVER w AS exp_prev
          FROM payment.ledger_entries le
        WINDOW w AS (PARTITION BY le.account_id ORDER BY le.account_seq)
    ), bad AS (
        SELECT c.id AS entry_id, c.account_id
          FROM chain c
         WHERE c.account_seq <> c.exp_seq
            OR c.prev_hash <> COALESCE(c.exp_prev, payment.fn_genesis_hash(c.account_id))
            OR c.entry_hash <> payment.fn_entry_hash(c.prev_hash, c.account_id, c.account_seq, c.transaction_id,
                                                      c.direction, c.amount_minor, c.currency, c.balance_after_minor)
    )
    SELECT 'LEDGER_HASH_CHAIN', 'CRITICAL'::payment.check_severity, count(*) = 0, count(*),
           COALESCE((SELECT jsonb_agg(to_jsonb(s)) FROM (SELECT * FROM bad ORDER BY entry_id LIMIT 5) s), '[]'::jsonb)
      FROM bad;

    -- C2 : continuité des soldes courants dans le grand livre.
    RETURN QUERY
    WITH running AS (
        SELECT le.id AS entry_id, le.account_id, le.balance_after_minor,
               a.opening_balance_minor + sum(CASE WHEN le.direction = 'CREDIT' THEN le.amount_minor ELSE -le.amount_minor END)
                   OVER (PARTITION BY le.account_id ORDER BY le.account_seq) AS exp_balance
          FROM payment.ledger_entries le
          JOIN payment.accounts a ON a.id = le.account_id
    ), bad AS (
        SELECT entry_id, account_id, balance_after_minor, exp_balance FROM running WHERE balance_after_minor <> exp_balance
    )
    SELECT 'LEDGER_RUNNING_BALANCE', 'CRITICAL'::payment.check_severity, count(*) = 0, count(*),
           COALESCE((SELECT jsonb_agg(to_jsonb(s)) FROM (SELECT * FROM bad ORDER BY entry_id LIMIT 5) s), '[]'::jsonb)
      FROM bad;

    -- C3 : projection des soldes conforme au grand livre.
    RETURN QUERY
    WITH bad AS (
        SELECT b.account_id, b.available_minor AS actual_balance, t.expected_balance_minor AS expected_balance,
               b.entry_count AS actual_count, t.expected_entry_count AS expected_count
          FROM payment.account_balances b
          JOIN payment.v_account_ledger_tail t ON t.account_id = b.account_id
         WHERE b.available_minor <> t.expected_balance_minor
            OR b.entry_count <> t.expected_entry_count
            OR b.last_entry_hash <> t.expected_last_hash
    )
    SELECT 'BALANCE_MATCHES_LEDGER', 'CRITICAL'::payment.check_severity, count(*) = 0, count(*),
           COALESCE((SELECT jsonb_agg(to_jsonb(s)) FROM (SELECT * FROM bad ORDER BY account_id LIMIT 5) s), '[]'::jsonb)
      FROM bad;

    -- C4 : partie double.
    RETURN QUERY
    WITH agg AS (
        SELECT t.id AS transaction_id, t.status, t.amount_minor,
               count(le.id) AS entries,
               COALESCE(sum(le.amount_minor) FILTER (WHERE le.direction = 'DEBIT'), 0)  AS debits,
               COALESCE(sum(le.amount_minor) FILTER (WHERE le.direction = 'CREDIT'), 0) AS credits
          FROM payment.transactions t
          LEFT JOIN payment.ledger_entries le ON le.transaction_id = t.id
         GROUP BY t.id, t.status, t.amount_minor
    ), bad AS (
        SELECT * FROM agg
         WHERE (status = 'EXECUTED' AND (entries <> 2 OR debits <> amount_minor OR credits <> amount_minor))
            OR (status <> 'EXECUTED' AND entries > 0)
    )
    SELECT 'DOUBLE_ENTRY', 'CRITICAL'::payment.check_severity, count(*) = 0, count(*),
           COALESCE((SELECT jsonb_agg(to_jsonb(s)) FROM (SELECT * FROM bad ORDER BY transaction_id LIMIT 5) s), '[]'::jsonb)
      FROM bad;

    -- C5 : conservation de la masse monétaire par devise.
    RETURN QUERY
    WITH totals AS (
        SELECT a.currency, sum(a.opening_balance_minor) AS expected_total, sum(b.available_minor) AS actual_total
          FROM payment.accounts a
          JOIN payment.account_balances b ON b.account_id = a.id
         GROUP BY a.currency
    ), bad AS (
        SELECT * FROM totals WHERE expected_total <> actual_total
    )
    SELECT 'MONEY_CONSERVATION', 'CRITICAL'::payment.check_severity, count(*) = 0, count(*),
           COALESCE((SELECT jsonb_agg(to_jsonb(s)) FROM (SELECT * FROM bad ORDER BY currency) s), '[]'::jsonb)
      FROM bad;

    -- C6 : ségrégation du trafic synthétique.
    RETURN QUERY
    WITH bad AS (
        SELECT t.id AS transaction_id
          FROM payment.transactions t
          JOIN payment.accounts d ON d.id = t.debit_account_id
          JOIN payment.accounts c ON c.id = t.credit_account_id
         WHERE d.is_synthetic <> t.is_synthetic OR c.is_synthetic <> t.is_synthetic
    )
    SELECT 'SYNTHETIC_SEGREGATION', 'CRITICAL'::payment.check_severity, count(*) = 0, count(*),
           COALESCE((SELECT jsonb_agg(to_jsonb(s)) FROM (SELECT * FROM bad ORDER BY transaction_id LIMIT 5) s), '[]'::jsonb)
      FROM bad;

    -- C7 : transactions bloquées en vol (état corrompu à purger).
    RETURN QUERY
    WITH bad AS (
        SELECT t.id AS transaction_id, t.status, t.created_at
          FROM payment.transactions t
         WHERE t.status IN ('PENDING', 'VALIDATED')
           AND t.created_at < clock_timestamp() - p_stale_after
    )
    SELECT 'STALE_IN_FLIGHT', 'WARNING'::payment.check_severity, count(*) = 0, count(*),
           COALESCE((SELECT jsonb_agg(to_jsonb(s)) FROM (SELECT * FROM bad ORDER BY created_at LIMIT 5) s), '[]'::jsonb)
      FROM bad;
END $$;

-- =============================================================================
-- Maintenance post-incident (réservé au rôle payment_maint)
-- =============================================================================
-- Reconstruit la projection des soldes depuis le grand livre.
-- Refuse d'agir si le grand livre lui-même est compromis (C1/C2 en échec) :
-- dans ce cas seule une restauration depuis sauvegarde est légitime (escalade).
CREATE FUNCTION payment.fn_repair_balances(p_reason text, p_incident_id uuid DEFAULT NULL, p_dry_run boolean DEFAULT false)
RETURNS TABLE (repaired_account_id uuid, field_name text, previous_value text, corrected_value text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
#variable_conflict use_column
DECLARE
    r record;
BEGIN
    IF p_reason IS NULL OR length(trim(p_reason)) < 5 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'a meaningful repair reason is required';
    END IF;

    -- Gèle toute écriture de solde pendant la réparation (lectures toujours possibles).
    LOCK TABLE payment.account_balances IN SHARE ROW EXCLUSIVE MODE;

    IF EXISTS (SELECT 1 FROM payment.fn_integrity_report() ir
                WHERE ir.check_code IN ('LEDGER_HASH_CHAIN', 'LEDGER_RUNNING_BALANCE') AND NOT ir.passed) THEN
        RAISE EXCEPTION USING ERRCODE = 'RA012',
            MESSAGE = 'ledger is compromised: automatic repair refused, restore from backup required';
    END IF;

    FOR r IN
        SELECT b.account_id, b.available_minor, b.entry_count, b.last_entry_hash,
               t.expected_balance_minor, t.expected_entry_count, t.expected_last_hash
          FROM payment.account_balances b
          JOIN payment.v_account_ledger_tail t ON t.account_id = b.account_id
         WHERE b.available_minor <> t.expected_balance_minor
            OR b.entry_count <> t.expected_entry_count
            OR b.last_entry_hash <> t.expected_last_hash
         ORDER BY b.account_id
    LOOP
        IF r.available_minor <> r.expected_balance_minor THEN
            repaired_account_id := r.account_id; field_name := 'available_minor';
            previous_value := r.available_minor::text; corrected_value := r.expected_balance_minor::text;
            RETURN NEXT;
        END IF;
        IF r.entry_count <> r.expected_entry_count THEN
            repaired_account_id := r.account_id; field_name := 'entry_count';
            previous_value := r.entry_count::text; corrected_value := r.expected_entry_count::text;
            RETURN NEXT;
        END IF;
        IF r.last_entry_hash <> r.expected_last_hash THEN
            repaired_account_id := r.account_id; field_name := 'last_entry_hash';
            previous_value := encode(r.last_entry_hash, 'hex'); corrected_value := encode(r.expected_last_hash, 'hex');
            RETURN NEXT;
        END IF;

        IF NOT p_dry_run THEN
            INSERT INTO payment.integrity_repairs (account_id, field_name, previous_value, corrected_value, reason, incident_id)
            SELECT r.account_id, f.name, f.prev, f.corr, p_reason, p_incident_id
              FROM (VALUES ('available_minor', r.available_minor::text, r.expected_balance_minor::text),
                           ('entry_count',     r.entry_count::text,     r.expected_entry_count::text),
                           ('last_entry_hash', encode(r.last_entry_hash, 'hex'), encode(r.expected_last_hash, 'hex'))
                   ) AS f(name, prev, corr)
             WHERE f.prev <> f.corr;

            UPDATE payment.account_balances
               SET available_minor = r.expected_balance_minor,
                   entry_count     = r.expected_entry_count,
                   last_entry_hash = r.expected_last_hash,
                   version         = version + 1,
                   updated_at      = clock_timestamp()
             WHERE account_id = r.account_id;
        END IF;
    END LOOP;
END $$;

-- Purge des transactions bloquées en vol : passage en FAILED (jamais de suppression).
CREATE FUNCTION payment.fn_fail_stale_transactions(p_older_than interval, p_reason text, p_incident_id uuid DEFAULT NULL)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, payment AS $$
DECLARE
    v_count integer;
BEGIN
    IF p_older_than < interval '60 seconds' THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'p_older_than must be >= 60 seconds';
    END IF;
    IF p_reason IS NULL OR length(trim(p_reason)) < 5 THEN
        RAISE EXCEPTION USING ERRCODE = '22023', MESSAGE = 'a meaningful purge reason is required';
    END IF;

    UPDATE payment.transactions
       SET status = 'FAILED',
           failure_code = 'STALE_PURGED',
           failure_reason = left(format('%s (incident=%s)', p_reason, COALESCE(p_incident_id::text, 'n/a')), 512)
     WHERE status IN ('PENDING', 'VALIDATED')
       AND created_at < clock_timestamp() - p_older_than;
    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END $$;

-- =============================================================================
-- Privilèges
-- =============================================================================
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA payment FROM PUBLIC;

-- payment_app : runtime métier. Ni UPDATE de solde, ni INSERT au grand livre :
-- toute écriture financière passe par fn_execute_transaction.
GRANT USAGE ON SCHEMA payment TO payment_app;
GRANT SELECT ON payment.currencies, payment.accounts, payment.account_balances, payment.transactions,
                payment.transaction_status_history, payment.ledger_entries, payment.runtime_flags,
                payment.integrity_reports TO payment_app;
GRANT INSERT ON payment.transactions TO payment_app;
GRANT UPDATE (status, failure_code, failure_reason) ON payment.transactions TO payment_app;
GRANT INSERT ON payment.integrity_reports TO payment_app;
GRANT EXECUTE ON FUNCTION payment.fn_execute_transaction(uuid) TO payment_app;
GRANT EXECUTE ON FUNCTION payment.fn_integrity_report(interval) TO payment_app;

-- payment_maint : actions de remédiation déclenchées via /admin (connexion dédiée).
GRANT USAGE ON SCHEMA payment TO payment_maint;
GRANT SELECT ON ALL TABLES IN SCHEMA payment TO payment_maint;
GRANT INSERT ON payment.runtime_flags, payment.integrity_reports TO payment_maint;
GRANT UPDATE (value, reason, updated_by, incident_id) ON payment.runtime_flags TO payment_maint;
GRANT UPDATE (status) ON payment.accounts TO payment_maint;
GRANT EXECUTE ON FUNCTION payment.fn_integrity_report(interval) TO payment_maint;
GRANT EXECUTE ON FUNCTION payment.fn_repair_balances(text, uuid, boolean) TO payment_maint;
GRANT EXECUTE ON FUNCTION payment.fn_fail_stale_transactions(interval, text, uuid) TO payment_maint;

COMMIT;
