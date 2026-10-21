-- =============================================================================
-- PROJECT RESILIENCE-ALPHA — 02 : base `ra_payment` (propriété fonctionnelle : payment-api)
-- -----------------------------------------------------------------------------
-- Données 100 % fictives. Montants en unités mineures (BIGINT), jamais en float.
--
-- Invariants garantis PAR LA BASE (défense en profondeur, indépendamment du code) :
--   I1  Un solde ne change QUE par l'écriture d'une ligne de grand livre.
--   I2  Le grand livre est append-only (ni UPDATE, ni DELETE ; TRUNCATE exige DROP).
--   I3  Partie double : une transaction EXECUTED a exactement 1 débit et 1 crédit
--       du même montant ; une transaction non EXECUTED n'a aucune écriture.
--   I4  Chaque compte porte une chaîne de hachage SHA-256 de ses écritures
--       (détection d'altération) ; une divergence solde/grand livre bloque l'écriture.
--   I5  Aucun solde négatif ; masse monétaire constante par devise.
--   I6  Machine à états des transactions stricte ; champs financiers immuables.
--   I7  Ségrégation des transactions synthétiques (comptes RA-9xxx uniquement).
--
-- Codes SQLSTATE applicatifs (classe RA0xx, repris en tête du message d'erreur) :
--   RA001 transaction introuvable      RA007 violation partie double
--   RA002 état invalide                RA008 transition interdite
--   RA003 provision insuffisante       RA009 divergence solde / grand livre
--   RA004 compte inactif               RA010 violation ségrégation synthétique
--   RA005 devise incohérente           RA011 champ immuable modifié
--   RA006 table append-only            RA012 grand livre compromis (réparation refusée)
-- =============================================================================
SET NAMES utf8mb4;
SET time_zone = '+00:00';
SET sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

CREATE DATABASE ra_payment CHARACTER SET utf8mb4 COLLATE utf8mb4_bin
    COMMENT 'Comptes fictifs, transactions, grand livre en partie double (payment-api)';

-- -----------------------------------------------------------------------------
-- Référentiel
-- -----------------------------------------------------------------------------
CREATE TABLE ra_payment.currencies (
    code        CHAR(3)     NOT NULL PRIMARY KEY,
    minor_units SMALLINT    NOT NULL,
    label       VARCHAR(64) NOT NULL,
    CONSTRAINT ck_currency_code  CHECK (code REGEXP '^[A-Z]{3}$'),
    CONSTRAINT ck_currency_minor CHECK (minor_units BETWEEN 0 AND 4)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Comptes & soldes
-- -----------------------------------------------------------------------------
CREATE TABLE ra_payment.accounts (
    id                    CHAR(36) CHARACTER SET ascii NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    account_number        VARCHAR(12)  NOT NULL
                          COMMENT 'Identifiant fictif RA-NNNN-NNNN (aucun IBAN réel). Plage RA-9xxx réservée au monitoring synthétique',
    owner_principal_id    CHAR(36) CHARACTER SET ascii NOT NULL
                          COMMENT 'Référence logique vers ra_auth.principals.id (pas de FK inter-base : découplage des services)',
    holder_name           VARCHAR(128) NOT NULL,
    currency              CHAR(3)      NOT NULL,
    status                ENUM('ACTIVE', 'FROZEN', 'CLOSED') NOT NULL DEFAULT 'ACTIVE',
    is_synthetic          BOOLEAN      NOT NULL DEFAULT FALSE,
    opening_balance_minor BIGINT       NOT NULL DEFAULT 0,
    created_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at            DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_accounts_number UNIQUE (account_number),
    INDEX ix_accounts_owner (owner_principal_id),
    CONSTRAINT fk_accounts_currency FOREIGN KEY (currency) REFERENCES ra_payment.currencies (code),
    CONSTRAINT ck_accounts_number_format CHECK (account_number REGEXP '^RA-[0-9]{4}-[0-9]{4}$'),
    CONSTRAINT ck_accounts_opening CHECK (opening_balance_minor >= 0),
    CONSTRAINT ck_accounts_synthetic_range CHECK (is_synthetic = (account_number LIKE 'RA-9%'))
) ENGINE = InnoDB;

CREATE TABLE ra_payment.account_balances (
    account_id      CHAR(36) CHARACTER SET ascii NOT NULL PRIMARY KEY,
    available_minor BIGINT        NOT NULL,
    entry_count     BIGINT        NOT NULL DEFAULT 0,
    last_entry_hash VARBINARY(32) NOT NULL,
    version         BIGINT        NOT NULL DEFAULT 0,
    updated_at      DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT fk_balances_account FOREIGN KEY (account_id) REFERENCES ra_payment.accounts (id) ON DELETE RESTRICT,
    CONSTRAINT ck_balance_non_negative CHECK (available_minor >= 0),
    CONSTRAINT ck_balance_entry_count  CHECK (entry_count >= 0),
    CONSTRAINT ck_balance_hash_len     CHECK (LENGTH(last_entry_hash) = 32)
) ENGINE = InnoDB COMMENT 'Projection matérialisée du grand livre ; jamais modifiable directement par ra_payment_app';

-- -----------------------------------------------------------------------------
-- Transactions & historique
-- -----------------------------------------------------------------------------
CREATE TABLE ra_payment.transactions (
    id                     CHAR(36) CHARACTER SET ascii NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    initiator_principal_id CHAR(36) CHARACTER SET ascii NOT NULL,
    idempotency_key        VARCHAR(64)   NOT NULL,
    request_fingerprint    VARBINARY(32) NOT NULL COMMENT 'SHA-256 du payload canonique : même clé + payload différent => 409',
    debit_account_id       CHAR(36) CHARACTER SET ascii NOT NULL,
    credit_account_id      CHAR(36) CHARACTER SET ascii NOT NULL,
    amount_minor           BIGINT        NOT NULL,
    currency               CHAR(3)       NOT NULL,
    description            VARCHAR(140),
    status                 ENUM('PENDING', 'VALIDATED', 'EXECUTED', 'REJECTED', 'FAILED', 'CANCELLED') NOT NULL DEFAULT 'PENDING',
    failure_code           VARCHAR(64),
    failure_reason         VARCHAR(512),
    is_synthetic           BOOLEAN       NOT NULL DEFAULT FALSE,
    correlation_id         VARCHAR(64),
    created_at             DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    validated_at           DATETIME(6),
    executed_at            DATETIME(6),
    updated_at             DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_transactions_idempotency UNIQUE (initiator_principal_id, idempotency_key),
    INDEX ix_tx_created           (created_at, id),
    INDEX ix_tx_debit_created     (debit_account_id, created_at),
    INDEX ix_tx_credit_created    (credit_account_id, created_at),
    INDEX ix_tx_initiator_created (initiator_principal_id, created_at),
    INDEX ix_tx_in_flight         (status, created_at),
    CONSTRAINT fk_tx_debit    FOREIGN KEY (debit_account_id)  REFERENCES ra_payment.accounts (id),
    CONSTRAINT fk_tx_credit   FOREIGN KEY (credit_account_id) REFERENCES ra_payment.accounts (id),
    CONSTRAINT fk_tx_currency FOREIGN KEY (currency)          REFERENCES ra_payment.currencies (code),
    CONSTRAINT ck_tx_idempotency_key   CHECK (idempotency_key REGEXP '^[A-Za-z0-9_:.-]{8,64}$'),
    CONSTRAINT ck_tx_fingerprint_len   CHECK (LENGTH(request_fingerprint) = 32),
    CONSTRAINT ck_tx_distinct_accounts CHECK (debit_account_id <> credit_account_id),
    CONSTRAINT ck_tx_amount            CHECK (amount_minor > 0 AND amount_minor <= 100000000000),
    CONSTRAINT ck_tx_failure           CHECK ((status IN ('REJECTED', 'FAILED')) = (failure_code IS NOT NULL)),
    CONSTRAINT ck_tx_failure_code      CHECK (failure_code IS NULL OR failure_code REGEXP '^[A-Z][A-Z_]+$'),
    CONSTRAINT ck_tx_validated_at      CHECK (status NOT IN ('VALIDATED', 'EXECUTED') OR validated_at IS NOT NULL),
    CONSTRAINT ck_tx_executed_at       CHECK ((status = 'EXECUTED') = (executed_at IS NOT NULL))
) ENGINE = InnoDB;

CREATE TABLE ra_payment.transaction_status_history (
    id             BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    transaction_id CHAR(36) CHARACTER SET ascii NOT NULL,
    from_status    ENUM('PENDING', 'VALIDATED', 'EXECUTED', 'REJECTED', 'FAILED', 'CANCELLED'),
    to_status      ENUM('PENDING', 'VALIDATED', 'EXECUTED', 'REJECTED', 'FAILED', 'CANCELLED') NOT NULL,
    failure_code   VARCHAR(64),
    changed_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    db_user        VARCHAR(128) NOT NULL,
    INDEX ix_tx_history_tx (transaction_id, id),
    CONSTRAINT fk_tx_history_tx FOREIGN KEY (transaction_id) REFERENCES ra_payment.transactions (id)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Grand livre en partie double, chaîné par compte
-- -----------------------------------------------------------------------------
-- account_seq, balance_after_minor, prev_hash et entry_hash sont calculés par
-- trg_ledger_before_insert (les valeurs par défaut ne sont jamais conservées).
CREATE TABLE ra_payment.ledger_entries (
    id                  BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    transaction_id      CHAR(36) CHARACTER SET ascii NOT NULL,
    account_id          CHAR(36) CHARACTER SET ascii NOT NULL,
    direction           ENUM('DEBIT', 'CREDIT') NOT NULL,
    amount_minor        BIGINT        NOT NULL,
    currency            CHAR(3)       NOT NULL,
    account_seq         BIGINT        NOT NULL DEFAULT 0,
    balance_after_minor BIGINT        NOT NULL DEFAULT 0,
    prev_hash           VARBINARY(32) NOT NULL DEFAULT '',
    entry_hash          VARBINARY(32) NOT NULL DEFAULT ''
                        COMMENT 'SHA-256(prev_hash || account|seq|tx|direction|amount|currency|balance_after)',
    created_at          DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_ledger_account_seq  UNIQUE (account_id, account_seq),
    CONSTRAINT uq_ledger_tx_direction UNIQUE (transaction_id, direction),
    CONSTRAINT fk_ledger_tx       FOREIGN KEY (transaction_id) REFERENCES ra_payment.transactions (id),
    CONSTRAINT fk_ledger_account  FOREIGN KEY (account_id)     REFERENCES ra_payment.accounts (id),
    CONSTRAINT fk_ledger_currency FOREIGN KEY (currency)       REFERENCES ra_payment.currencies (code),
    CONSTRAINT ck_ledger_amount   CHECK (amount_minor > 0),
    CONSTRAINT ck_ledger_seq      CHECK (account_seq > 0),
    CONSTRAINT ck_ledger_balance  CHECK (balance_after_minor >= 0),
    CONSTRAINT ck_ledger_hash_len CHECK (LENGTH(prev_hash) = 32 AND LENGTH(entry_hash) = 32)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Configuration dynamique (reconfiguration à chaud par le moteur de remédiation)
-- -----------------------------------------------------------------------------
CREATE TABLE ra_payment.runtime_flags (
    `key`       VARCHAR(64)  NOT NULL PRIMARY KEY,
    value       JSON         NOT NULL
                COMMENT 'write_mode : READ_WRITE | SYNTHETIC_ONLY (quarantaine : seul le trafic synthétique passe) | READ_ONLY',
    reason      VARCHAR(256) NOT NULL,
    updated_by  CHAR(36) CHARACTER SET ascii,
    incident_id CHAR(36) CHARACTER SET ascii,
    updated_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT ck_flags_key CHECK (`key` IN ('write_mode', 'max_transaction_amount_minor', 'max_requests_per_minute_per_principal')),
    CONSTRAINT ck_flags_value CHECK (
        CASE
            WHEN `key` = 'write_mode' THEN JSON_TYPE(value) = 'STRING'
                                       AND JSON_UNQUOTE(value) IN ('READ_WRITE', 'SYNTHETIC_ONLY', 'READ_ONLY')
            ELSE JSON_TYPE(value) IN ('INTEGER', 'DOUBLE') AND CAST(value AS DOUBLE) > 0
        END
    )
) ENGINE = InnoDB;

CREATE TABLE ra_payment.runtime_flag_changes (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    `key`       VARCHAR(64)  NOT NULL,
    old_value   JSON,
    new_value   JSON         NOT NULL,
    reason      VARCHAR(256) NOT NULL,
    updated_by  CHAR(36) CHARACTER SET ascii,
    incident_id CHAR(36) CHARACTER SET ascii,
    changed_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    db_user     VARCHAR(128) NOT NULL
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Intégrité : rapports et réparations tracées
-- -----------------------------------------------------------------------------
CREATE TABLE ra_payment.integrity_reports (
    id                CHAR(36) CHARACTER SET ascii NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    generated_at      DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    trigger_source    VARCHAR(16) NOT NULL,
    passed            BOOLEAN     NOT NULL,
    critical_failures INT         NOT NULL,
    warnings          INT         NOT NULL,
    duration_ms       INT         NOT NULL,
    checks            JSON        NOT NULL,
    incident_id       CHAR(36) CHARACTER SET ascii,
    INDEX ix_integrity_reports_generated (generated_at),
    CONSTRAINT ck_integrity_trigger CHECK (trigger_source IN ('HEALTH_PROBE', 'REMEDIATION', 'SCHEDULED', 'OPERATOR')),
    CONSTRAINT ck_integrity_counts CHECK (critical_failures >= 0 AND warnings >= 0 AND duration_ms >= 0),
    CONSTRAINT ck_integrity_passed CHECK (passed = (critical_failures = 0))
) ENGINE = InnoDB;

CREATE TABLE ra_payment.integrity_repairs (
    id              BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    repaired_at     DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    account_id      CHAR(36) CHARACTER SET ascii NOT NULL,
    field_name      VARCHAR(32)  NOT NULL,
    previous_value  TEXT         NOT NULL,
    corrected_value TEXT         NOT NULL,
    reason          VARCHAR(256) NOT NULL,
    incident_id     CHAR(36) CHARACTER SET ascii,
    db_user         VARCHAR(128) NOT NULL,
    CONSTRAINT fk_repairs_account FOREIGN KEY (account_id) REFERENCES ra_payment.accounts (id)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Événements temps réel (outbox) : écrits DANS la transaction métier, donc
-- visibles uniquement après COMMIT ; chaque instance de payment-api les relit.
-- -----------------------------------------------------------------------------
CREATE TABLE ra_payment.event_outbox (
    id         BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    payload    TEXT        NOT NULL,
    created_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX ix_event_outbox_created (created_at)
) ENGINE = InnoDB;

-- =============================================================================
-- Fonctions utilitaires
-- =============================================================================
DELIMITER $$

CREATE DEFINER = 'ra_owner'@'localhost' FUNCTION ra_payment.fn_genesis_hash(p_account_id CHAR(36))
RETURNS VARBINARY(32) DETERMINISTIC NO SQL
    RETURN UNHEX(SHA2(CONCAT('RA-GENESIS|', p_account_id), 256)) $$

CREATE DEFINER = 'ra_owner'@'localhost' FUNCTION ra_payment.fn_entry_hash(
    p_prev_hash     VARBINARY(32),
    p_account_id    CHAR(36),
    p_account_seq   BIGINT,
    p_tx_id         CHAR(36),
    p_direction     VARCHAR(6),
    p_amount_minor  BIGINT,
    p_currency      CHAR(3),
    p_balance_after BIGINT
) RETURNS VARBINARY(32) DETERMINISTIC NO SQL
    RETURN UNHEX(SHA2(CONCAT(p_prev_hash, CONCAT_WS('|', p_account_id, p_account_seq, p_tx_id, p_direction,
                                                    p_amount_minor, p_currency, p_balance_after)), 256)) $$

DELIMITER ;

-- Dernier état connu de chaque compte d'après le grand livre (source de vérité).
CREATE DEFINER = 'ra_owner'@'localhost' SQL SECURITY DEFINER VIEW ra_payment.v_account_ledger_tail AS
SELECT a.id                                                      AS account_id,
       COALESCE(t.balance_after_minor, a.opening_balance_minor)  AS expected_balance_minor,
       COALESCE(t.account_seq, 0)                                AS expected_entry_count,
       COALESCE(t.entry_hash, ra_payment.fn_genesis_hash(a.id))  AS expected_last_hash
  FROM ra_payment.accounts a
  LEFT JOIN ra_payment.ledger_entries t
    ON t.account_id = a.id
   AND t.account_seq = (SELECT MAX(le.account_seq) FROM ra_payment.ledger_entries le WHERE le.account_id = a.id);

DELIMITER $$

-- =============================================================================
-- Déclencheurs : comptes
-- =============================================================================
CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_accounts_after_insert
AFTER INSERT ON ra_payment.accounts FOR EACH ROW
    INSERT INTO ra_payment.account_balances (account_id, available_minor, entry_count, last_entry_hash)
    VALUES (NEW.id, NEW.opening_balance_minor, 0, ra_payment.fn_genesis_hash(NEW.id)) $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_accounts_before_update
BEFORE UPDATE ON ra_payment.accounts FOR EACH ROW
BEGIN
    DECLARE v_msg VARCHAR(128);
    IF NOT (NEW.id <=> OLD.id AND NEW.account_number <=> OLD.account_number
            AND NEW.owner_principal_id <=> OLD.owner_principal_id AND NEW.currency <=> OLD.currency
            AND NEW.is_synthetic <=> OLD.is_synthetic AND NEW.opening_balance_minor <=> OLD.opening_balance_minor
            AND NEW.created_at <=> OLD.created_at) THEN
        SET v_msg = CONCAT('RA011 immutable account fields modified on ', OLD.id);
        SIGNAL SQLSTATE 'RA011' SET MESSAGE_TEXT = v_msg;
    END IF;
    SET NEW.updated_at = SYSDATE(6);
END $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_account_balances_no_delete
BEFORE DELETE ON ra_payment.account_balances FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.account_balances is append-only' $$

-- =============================================================================
-- Déclencheurs : transactions (machine à états, immutabilité, historique)
-- =============================================================================
CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_transactions_before_insert
BEFORE INSERT ON ra_payment.transactions FOR EACH ROW
BEGIN
    DECLARE v_debit_currency  CHAR(3);
    DECLARE v_credit_currency CHAR(3);
    DECLARE v_debit_synthetic, v_credit_synthetic BOOLEAN;
    DECLARE v_msg VARCHAR(128);

    IF NEW.status <> 'PENDING' THEN
        SIGNAL SQLSTATE 'RA008' SET MESSAGE_TEXT = 'RA008 a transaction must be created in PENDING status';
    END IF;

    SELECT currency, is_synthetic INTO v_debit_currency, v_debit_synthetic
      FROM ra_payment.accounts WHERE id = NEW.debit_account_id;
    SELECT currency, is_synthetic INTO v_credit_currency, v_credit_synthetic
      FROM ra_payment.accounts WHERE id = NEW.credit_account_id;
    IF v_debit_currency IS NOT NULL AND v_credit_currency IS NOT NULL THEN
        IF v_debit_currency <> NEW.currency OR v_credit_currency <> NEW.currency THEN
            SET v_msg = CONCAT('RA005 currency mismatch: tx=', NEW.currency, ' debit=', v_debit_currency, ' credit=', v_credit_currency);
            SIGNAL SQLSTATE 'RA005' SET MESSAGE_TEXT = v_msg;
        END IF;
        IF v_debit_synthetic <> NEW.is_synthetic OR v_credit_synthetic <> NEW.is_synthetic THEN
            SIGNAL SQLSTATE 'RA010'
                SET MESSAGE_TEXT = 'RA010 synthetic transactions must only involve synthetic accounts (and vice versa)';
        END IF;
    END IF;

    SET NEW.created_at   = SYSDATE(6);
    SET NEW.updated_at   = NEW.created_at;
    SET NEW.validated_at = NULL;
    SET NEW.executed_at  = NULL;
END $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_transactions_before_update
BEFORE UPDATE ON ra_payment.transactions FOR EACH ROW
BEGIN
    DECLARE v_entries INT;
    DECLARE v_msg VARCHAR(128);

    IF NOT (NEW.id <=> OLD.id AND NEW.initiator_principal_id <=> OLD.initiator_principal_id
            AND NEW.idempotency_key <=> OLD.idempotency_key AND NEW.request_fingerprint <=> OLD.request_fingerprint
            AND NEW.debit_account_id <=> OLD.debit_account_id AND NEW.credit_account_id <=> OLD.credit_account_id
            AND NEW.amount_minor <=> OLD.amount_minor AND NEW.currency <=> OLD.currency
            AND NEW.description <=> OLD.description AND NEW.is_synthetic <=> OLD.is_synthetic
            AND NEW.correlation_id <=> OLD.correlation_id AND NEW.created_at <=> OLD.created_at) THEN
        SET v_msg = CONCAT('RA011 immutable transaction fields modified on ', OLD.id);
        SIGNAL SQLSTATE 'RA011' SET MESSAGE_TEXT = v_msg;
    END IF;

    -- Les horodatages de cycle de vie sont posés exclusivement par la base.
    SET NEW.validated_at = OLD.validated_at;
    SET NEW.executed_at  = OLD.executed_at;

    IF NOT (NEW.status <=> OLD.status) THEN
        IF NOT (
               (OLD.status = 'PENDING'   AND NEW.status IN ('VALIDATED', 'REJECTED', 'FAILED', 'CANCELLED'))
            OR (OLD.status = 'VALIDATED' AND NEW.status IN ('EXECUTED', 'REJECTED', 'FAILED', 'CANCELLED'))
        ) THEN
            SET v_msg = CONCAT('RA008 illegal transition ', OLD.status, ' -> ', NEW.status, ' for transaction ', OLD.id);
            SIGNAL SQLSTATE 'RA008' SET MESSAGE_TEXT = v_msg;
        END IF;

        IF NEW.status = 'VALIDATED' THEN
            SET NEW.validated_at = SYSDATE(6);
        ELSEIF NEW.status = 'EXECUTED' THEN
            SELECT COUNT(*) INTO v_entries FROM ra_payment.ledger_entries WHERE transaction_id = NEW.id;
            IF v_entries <> 2 THEN
                SET v_msg = CONCAT('RA007 transaction ', NEW.id, ' cannot be EXECUTED with ', v_entries, ' ledger entries');
                SIGNAL SQLSTATE 'RA007' SET MESSAGE_TEXT = v_msg;
            END IF;
            SET NEW.executed_at = SYSDATE(6);
        END IF;
    ELSEIF OLD.status IN ('EXECUTED', 'REJECTED', 'FAILED', 'CANCELLED')
           AND NOT (NEW.failure_code <=> OLD.failure_code AND NEW.failure_reason <=> OLD.failure_reason) THEN
        SET v_msg = CONCAT('RA011 terminal transaction ', OLD.id, ' is immutable');
        SIGNAL SQLSTATE 'RA011' SET MESSAGE_TEXT = v_msg;
    END IF;

    SET NEW.updated_at = SYSDATE(6);
END $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_transactions_history_insert
AFTER INSERT ON ra_payment.transactions FOR EACH ROW
    INSERT INTO ra_payment.transaction_status_history (transaction_id, from_status, to_status, failure_code, changed_at, db_user)
    VALUES (NEW.id, NULL, NEW.status, NEW.failure_code, SYSDATE(6), SESSION_USER()) $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_transactions_history_update
AFTER UPDATE ON ra_payment.transactions FOR EACH ROW
BEGIN
    IF NOT (NEW.status <=> OLD.status) THEN
        INSERT INTO ra_payment.transaction_status_history (transaction_id, from_status, to_status, failure_code, changed_at, db_user)
        VALUES (NEW.id, OLD.status, NEW.status, NEW.failure_code, SYSDATE(6), SESSION_USER());
    END IF;
END $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_transactions_no_delete
BEFORE DELETE ON ra_payment.transactions FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.transactions is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_tx_history_no_update
BEFORE UPDATE ON ra_payment.transaction_status_history FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.transaction_status_history is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_tx_history_no_delete
BEFORE DELETE ON ra_payment.transaction_status_history FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.transaction_status_history is append-only' $$

-- =============================================================================
-- Déclencheur : grand livre (I3 partiel, I4, I5)
-- =============================================================================
CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_ledger_before_insert
BEFORE INSERT ON ra_payment.ledger_entries FOR EACH ROW
BEGIN
    DECLARE v_tx_status      VARCHAR(16);
    DECLARE v_tx_amount      BIGINT;
    DECLARE v_tx_currency    CHAR(3);
    DECLARE v_tx_debit       CHAR(36);
    DECLARE v_tx_credit      CHAR(36);
    DECLARE v_account_number VARCHAR(12);
    DECLARE v_account_status VARCHAR(16);
    DECLARE v_balance        BIGINT;
    DECLARE v_count          BIGINT;
    DECLARE v_hash           VARBINARY(32);
    DECLARE v_tail_balance   BIGINT;
    DECLARE v_tail_count     BIGINT;
    DECLARE v_tail_hash      VARBINARY(32);
    DECLARE v_new_balance    BIGINT;
    DECLARE v_msg            VARCHAR(128);

    SELECT status, amount_minor, currency, debit_account_id, credit_account_id
      INTO v_tx_status, v_tx_amount, v_tx_currency, v_tx_debit, v_tx_credit
      FROM ra_payment.transactions WHERE id = NEW.transaction_id;
    IF v_tx_status IS NULL THEN
        SET v_msg = CONCAT('RA001 transaction ', NEW.transaction_id, ' not found');
        SIGNAL SQLSTATE 'RA001' SET MESSAGE_TEXT = v_msg;
    END IF;
    IF v_tx_status <> 'VALIDATED' THEN
        SET v_msg = CONCAT('RA002 ledger entries require a VALIDATED transaction (', NEW.transaction_id, ' is ', v_tx_status, ')');
        SIGNAL SQLSTATE 'RA002' SET MESSAGE_TEXT = v_msg;
    END IF;
    IF NOT (NEW.amount_minor <=> v_tx_amount) OR NOT (NEW.currency <=> v_tx_currency)
       OR (NEW.direction = 'DEBIT'  AND NEW.account_id <> v_tx_debit)
       OR (NEW.direction = 'CREDIT' AND NEW.account_id <> v_tx_credit) THEN
        SET v_msg = CONCAT('RA007 ledger entry does not match transaction ', NEW.transaction_id);
        SIGNAL SQLSTATE 'RA007' SET MESSAGE_TEXT = v_msg;
    END IF;

    SELECT account_number, status INTO v_account_number, v_account_status
      FROM ra_payment.accounts WHERE id = NEW.account_id;
    IF v_account_status <> 'ACTIVE' THEN
        SET v_msg = CONCAT('RA004 account ', v_account_number, ' is ', v_account_status);
        SIGNAL SQLSTATE 'RA004' SET MESSAGE_TEXT = v_msg;
    END IF;

    SELECT available_minor, entry_count, last_entry_hash INTO v_balance, v_count, v_hash
      FROM ra_payment.account_balances WHERE account_id = NEW.account_id FOR UPDATE;

    -- Fin de chaîne d'après le grand livre (même définition que v_account_ledger_tail).
    SET v_tail_balance = NULL;
    SELECT balance_after_minor, account_seq, entry_hash INTO v_tail_balance, v_tail_count, v_tail_hash
      FROM ra_payment.ledger_entries WHERE account_id = NEW.account_id ORDER BY account_seq DESC LIMIT 1;
    IF v_tail_balance IS NULL THEN
        SELECT opening_balance_minor INTO v_tail_balance FROM ra_payment.accounts WHERE id = NEW.account_id;
        SET v_tail_count = 0;
        SET v_tail_hash = ra_payment.fn_genesis_hash(NEW.account_id);
    END IF;

    -- I4 : refus d'écrire sur un compte dont le solde a divergé du grand livre (altération détectée).
    IF v_balance <> v_tail_balance OR v_count <> v_tail_count OR v_hash <> v_tail_hash THEN
        SET v_msg = CONCAT('RA009 balance/ledger divergence on account ', v_account_number,
                           ' (balance=', v_balance, ' expected=', v_tail_balance, ')');
        SIGNAL SQLSTATE 'RA009' SET MESSAGE_TEXT = v_msg;
    END IF;

    SET v_new_balance = IF(NEW.direction = 'DEBIT', v_tail_balance - NEW.amount_minor, v_tail_balance + NEW.amount_minor);
    IF v_new_balance < 0 THEN
        SET v_msg = CONCAT('RA003 insufficient funds on account ', v_account_number);
        SIGNAL SQLSTATE 'RA003' SET MESSAGE_TEXT = v_msg;
    END IF;

    SET NEW.account_seq         = v_tail_count + 1;
    SET NEW.balance_after_minor = v_new_balance;
    SET NEW.prev_hash           = v_tail_hash;
    SET NEW.created_at          = SYSDATE(6);
    SET NEW.entry_hash          = ra_payment.fn_entry_hash(NEW.prev_hash, NEW.account_id, NEW.account_seq, NEW.transaction_id,
                                                           NEW.direction, NEW.amount_minor, NEW.currency, NEW.balance_after_minor);

    UPDATE ra_payment.account_balances
       SET available_minor = v_new_balance,
           entry_count     = NEW.account_seq,
           last_entry_hash = NEW.entry_hash,
           version         = version + 1,
           updated_at      = SYSDATE(6)
     WHERE account_id = NEW.account_id;
END $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_ledger_no_update
BEFORE UPDATE ON ra_payment.ledger_entries FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.ledger_entries is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_ledger_no_delete
BEFORE DELETE ON ra_payment.ledger_entries FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.ledger_entries is append-only' $$

-- =============================================================================
-- Déclencheurs : configuration dynamique (journalisation systématique) et réparations
-- =============================================================================
CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_runtime_flags_audit_insert
AFTER INSERT ON ra_payment.runtime_flags FOR EACH ROW
    INSERT INTO ra_payment.runtime_flag_changes (`key`, old_value, new_value, reason, updated_by, incident_id, changed_at, db_user)
    VALUES (NEW.`key`, NULL, NEW.value, NEW.reason, NEW.updated_by, NEW.incident_id, SYSDATE(6), SESSION_USER()) $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_runtime_flags_audit_update
AFTER UPDATE ON ra_payment.runtime_flags FOR EACH ROW
    INSERT INTO ra_payment.runtime_flag_changes (`key`, old_value, new_value, reason, updated_by, incident_id, changed_at, db_user)
    VALUES (NEW.`key`, OLD.value, NEW.value, NEW.reason, NEW.updated_by, NEW.incident_id, SYSDATE(6), SESSION_USER()) $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_runtime_flag_changes_no_update
BEFORE UPDATE ON ra_payment.runtime_flag_changes FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.runtime_flag_changes is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_runtime_flag_changes_no_delete
BEFORE DELETE ON ra_payment.runtime_flag_changes FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.runtime_flag_changes is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_integrity_repairs_no_update
BEFORE UPDATE ON ra_payment.integrity_repairs FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.integrity_repairs is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_payment.trg_integrity_repairs_no_delete
BEFORE DELETE ON ra_payment.integrity_repairs FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_payment.integrity_repairs is append-only' $$

-- =============================================================================
-- Primitive transactionnelle : exécution atomique d'une transaction VALIDATED
-- =============================================================================
-- Idempotente (une transaction déjà EXECUTED est renvoyée telle quelle).
-- Verrouillage ordonné des soldes (par account_id) => aucun interblocage.
-- Les refus métier (compte inactif, provision insuffisante) sont historisés
-- en REJECTED, sans erreur. Renvoie la ligne de la transaction.
-- Une erreur en cours d'exécution laisse des écritures partielles : l'appelant
-- exécute toujours la procédure dans une transaction (ou un SAVEPOINT) annulée en cas d'erreur.
CREATE DEFINER = 'ra_owner'@'localhost' PROCEDURE ra_payment.sp_execute_transaction(IN p_transaction_id CHAR(36))
MODIFIES SQL DATA SQL SECURITY DEFINER
proc: BEGIN
    DECLARE v_status        VARCHAR(16);
    DECLARE v_debit         CHAR(36);
    DECLARE v_credit        CHAR(36);
    DECLARE v_amount        BIGINT;
    DECLARE v_currency      CHAR(3);
    DECLARE v_debit_status  VARCHAR(16);
    DECLARE v_credit_status VARCHAR(16);
    DECLARE v_available     BIGINT;
    DECLARE v_count         INT;
    DECLARE v_debits        BIGINT;
    DECLARE v_credits       BIGINT;
    DECLARE v_msg           VARCHAR(128);

    SELECT status, debit_account_id, credit_account_id, amount_minor, currency
      INTO v_status, v_debit, v_credit, v_amount, v_currency
      FROM ra_payment.transactions WHERE id = p_transaction_id FOR UPDATE;
    IF v_status IS NULL THEN
        SET v_msg = CONCAT('RA001 transaction ', p_transaction_id, ' not found');
        SIGNAL SQLSTATE 'RA001' SET MESSAGE_TEXT = v_msg;
    END IF;
    IF v_status = 'EXECUTED' THEN
        SELECT * FROM ra_payment.transactions WHERE id = p_transaction_id;
        LEAVE proc;
    END IF;
    IF v_status <> 'VALIDATED' THEN
        SET v_msg = CONCAT('RA002 transaction ', p_transaction_id, ' is ', v_status, ', expected VALIDATED');
        SIGNAL SQLSTATE 'RA002' SET MESSAGE_TEXT = v_msg;
    END IF;

    SELECT available_minor INTO v_available FROM ra_payment.account_balances WHERE account_id = LEAST(v_debit, v_credit) FOR UPDATE;
    SELECT available_minor INTO v_available FROM ra_payment.account_balances WHERE account_id = GREATEST(v_debit, v_credit) FOR UPDATE;

    SELECT status INTO v_debit_status  FROM ra_payment.accounts WHERE id = v_debit;
    SELECT status INTO v_credit_status FROM ra_payment.accounts WHERE id = v_credit;

    IF v_debit_status <> 'ACTIVE' OR v_credit_status <> 'ACTIVE' THEN
        UPDATE ra_payment.transactions
           SET status = 'REJECTED', failure_code = 'ACCOUNT_NOT_ACTIVE',
               failure_reason = CONCAT('debit=', v_debit_status, ' credit=', v_credit_status)
         WHERE id = p_transaction_id;
        SELECT * FROM ra_payment.transactions WHERE id = p_transaction_id;
        LEAVE proc;
    END IF;

    SELECT available_minor INTO v_available FROM ra_payment.account_balances WHERE account_id = v_debit;
    IF v_available < v_amount THEN
        UPDATE ra_payment.transactions
           SET status = 'REJECTED', failure_code = 'INSUFFICIENT_FUNDS',
               failure_reason = 'available balance lower than requested amount'
         WHERE id = p_transaction_id;
        SELECT * FROM ra_payment.transactions WHERE id = p_transaction_id;
        LEAVE proc;
    END IF;

    INSERT INTO ra_payment.ledger_entries (transaction_id, account_id, direction, amount_minor, currency)
    VALUES (p_transaction_id, v_debit,  'DEBIT',  v_amount, v_currency),
           (p_transaction_id, v_credit, 'CREDIT', v_amount, v_currency);

    UPDATE ra_payment.transactions SET status = 'EXECUTED' WHERE id = p_transaction_id;

    -- I3 : contrôle de partie double (PostgreSQL le faisait en déclencheur différé ;
    -- cette procédure est le seul chemin d'écriture au grand livre).
    SELECT COUNT(*), COALESCE(SUM(IF(direction = 'DEBIT', amount_minor, 0)), 0), COALESCE(SUM(IF(direction = 'CREDIT', amount_minor, 0)), 0)
      INTO v_count, v_debits, v_credits
      FROM ra_payment.ledger_entries WHERE transaction_id = p_transaction_id;
    IF v_count <> 2 OR v_debits <> v_amount OR v_credits <> v_amount THEN
        SET v_msg = CONCAT('RA007 double-entry violation on transaction ', p_transaction_id);
        SIGNAL SQLSTATE 'RA007' SET MESSAGE_TEXT = v_msg;
    END IF;

    SELECT * FROM ra_payment.transactions WHERE id = p_transaction_id;
END $$

-- =============================================================================
-- Rapport d'intégrité (consommé par /health/integrity et par la remédiation)
-- =============================================================================
-- Remplit la table temporaire tmp_integrity_report (une ligne par contrôle).
CREATE DEFINER = 'ra_owner'@'localhost' PROCEDURE ra_payment.sp_integrity_fill(IN p_stale_after_seconds INT)
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    CREATE OR REPLACE TEMPORARY TABLE tmp_integrity_report (
        check_code VARCHAR(32) NOT NULL,
        severity   VARCHAR(8)  NOT NULL,
        passed     BOOLEAN     NOT NULL,
        violations BIGINT      NOT NULL,
        sample     TEXT        NOT NULL,
        seq        INT         NOT NULL AUTO_INCREMENT PRIMARY KEY
    );

    -- C1 : chaîne de hachage et séquence par compte (altération du grand livre).
    INSERT INTO tmp_integrity_report (check_code, severity, passed, violations, sample)
    SELECT 'LEDGER_HASH_CHAIN', 'CRITICAL', COUNT(*) = 0, COUNT(*),
           COALESCE(JSON_ARRAYAGG(JSON_OBJECT('entry_id', entry_id, 'account_id', account_id) ORDER BY entry_id LIMIT 5), '[]')
      FROM (
        SELECT c.id AS entry_id, c.account_id
          FROM (SELECT le.*,
                       ROW_NUMBER() OVER (PARTITION BY le.account_id ORDER BY le.account_seq) AS exp_seq,
                       LAG(le.entry_hash) OVER (PARTITION BY le.account_id ORDER BY le.account_seq) AS exp_prev
                  FROM ra_payment.ledger_entries le) c
         WHERE c.account_seq <> c.exp_seq
            OR c.prev_hash <> COALESCE(c.exp_prev, ra_payment.fn_genesis_hash(c.account_id))
            OR c.entry_hash <> ra_payment.fn_entry_hash(c.prev_hash, c.account_id, c.account_seq, c.transaction_id,
                                                        c.direction, c.amount_minor, c.currency, c.balance_after_minor)
      ) bad;

    -- C2 : continuité des soldes courants dans le grand livre.
    INSERT INTO tmp_integrity_report (check_code, severity, passed, violations, sample)
    SELECT 'LEDGER_RUNNING_BALANCE', 'CRITICAL', COUNT(*) = 0, COUNT(*),
           COALESCE(JSON_ARRAYAGG(JSON_OBJECT('entry_id', entry_id, 'account_id', account_id,
                                              'balance_after_minor', balance_after_minor, 'exp_balance', exp_balance)
                                  ORDER BY entry_id LIMIT 5), '[]')
      FROM (
        SELECT * FROM (
            SELECT le.id AS entry_id, le.account_id, le.balance_after_minor,
                   a.opening_balance_minor + SUM(IF(le.direction = 'CREDIT', le.amount_minor, -le.amount_minor))
                       OVER (PARTITION BY le.account_id ORDER BY le.account_seq) AS exp_balance
              FROM ra_payment.ledger_entries le
              JOIN ra_payment.accounts a ON a.id = le.account_id
        ) running WHERE balance_after_minor <> exp_balance
      ) bad;

    -- C3 : projection des soldes conforme au grand livre.
    INSERT INTO tmp_integrity_report (check_code, severity, passed, violations, sample)
    SELECT 'BALANCE_MATCHES_LEDGER', 'CRITICAL', COUNT(*) = 0, COUNT(*),
           COALESCE(JSON_ARRAYAGG(JSON_OBJECT('account_id', account_id, 'actual_balance', actual_balance,
                                              'expected_balance', expected_balance, 'actual_count', actual_count,
                                              'expected_count', expected_count)
                                  ORDER BY account_id LIMIT 5), '[]')
      FROM (
        SELECT b.account_id, b.available_minor AS actual_balance, t.expected_balance_minor AS expected_balance,
               b.entry_count AS actual_count, t.expected_entry_count AS expected_count
          FROM ra_payment.account_balances b
          JOIN ra_payment.v_account_ledger_tail t ON t.account_id = b.account_id
         WHERE b.available_minor <> t.expected_balance_minor
            OR b.entry_count <> t.expected_entry_count
            OR b.last_entry_hash <> t.expected_last_hash
      ) bad;

    -- C4 : partie double.
    INSERT INTO tmp_integrity_report (check_code, severity, passed, violations, sample)
    SELECT 'DOUBLE_ENTRY', 'CRITICAL', COUNT(*) = 0, COUNT(*),
           COALESCE(JSON_ARRAYAGG(JSON_OBJECT('transaction_id', transaction_id, 'status', status, 'amount_minor', amount_minor,
                                              'entries', entries, 'debits', debits, 'credits', credits)
                                  ORDER BY transaction_id LIMIT 5), '[]')
      FROM (
        SELECT * FROM (
            SELECT t.id AS transaction_id, t.status, t.amount_minor,
                   COUNT(le.id) AS entries,
                   COALESCE(SUM(IF(le.direction = 'DEBIT', le.amount_minor, 0)), 0)  AS debits,
                   COALESCE(SUM(IF(le.direction = 'CREDIT', le.amount_minor, 0)), 0) AS credits
              FROM ra_payment.transactions t
              LEFT JOIN ra_payment.ledger_entries le ON le.transaction_id = t.id
             GROUP BY t.id, t.status, t.amount_minor
        ) agg
         WHERE (status = 'EXECUTED' AND (entries <> 2 OR debits <> amount_minor OR credits <> amount_minor))
            OR (status <> 'EXECUTED' AND entries > 0)
      ) bad;

    -- C5 : conservation de la masse monétaire par devise.
    INSERT INTO tmp_integrity_report (check_code, severity, passed, violations, sample)
    SELECT 'MONEY_CONSERVATION', 'CRITICAL', COUNT(*) = 0, COUNT(*),
           COALESCE(JSON_ARRAYAGG(JSON_OBJECT('currency', currency, 'expected_total', expected_total, 'actual_total', actual_total)
                                  ORDER BY currency), '[]')
      FROM (
        SELECT * FROM (
            SELECT a.currency, SUM(a.opening_balance_minor) AS expected_total, SUM(b.available_minor) AS actual_total
              FROM ra_payment.accounts a
              JOIN ra_payment.account_balances b ON b.account_id = a.id
             GROUP BY a.currency
        ) totals WHERE expected_total <> actual_total
      ) bad;

    -- C6 : ségrégation du trafic synthétique.
    INSERT INTO tmp_integrity_report (check_code, severity, passed, violations, sample)
    SELECT 'SYNTHETIC_SEGREGATION', 'CRITICAL', COUNT(*) = 0, COUNT(*),
           COALESCE(JSON_ARRAYAGG(JSON_OBJECT('transaction_id', transaction_id) ORDER BY transaction_id LIMIT 5), '[]')
      FROM (
        SELECT t.id AS transaction_id
          FROM ra_payment.transactions t
          JOIN ra_payment.accounts d ON d.id = t.debit_account_id
          JOIN ra_payment.accounts c ON c.id = t.credit_account_id
         WHERE d.is_synthetic <> t.is_synthetic OR c.is_synthetic <> t.is_synthetic
      ) bad;

    -- C7 : transactions bloquées en vol (état corrompu à purger).
    INSERT INTO tmp_integrity_report (check_code, severity, passed, violations, sample)
    SELECT 'STALE_IN_FLIGHT', 'WARNING', COUNT(*) = 0, COUNT(*),
           COALESCE(JSON_ARRAYAGG(JSON_OBJECT('transaction_id', transaction_id, 'status', status,
                                              'created_at', DATE_FORMAT(created_at, '%Y-%m-%dT%H:%i:%s.%fZ'))
                                  ORDER BY created_at LIMIT 5), '[]')
      FROM (
        SELECT t.id AS transaction_id, t.status, t.created_at
          FROM ra_payment.transactions t
         WHERE t.status IN ('PENDING', 'VALIDATED')
           AND t.created_at < SYSDATE(6) - INTERVAL p_stale_after_seconds SECOND
      ) bad;
END $$

CREATE DEFINER = 'ra_owner'@'localhost' PROCEDURE ra_payment.sp_integrity_report(IN p_stale_after_seconds INT)
READS SQL DATA SQL SECURITY DEFINER
BEGIN
    CALL ra_payment.sp_integrity_fill(COALESCE(p_stale_after_seconds, 300));
    SELECT check_code, severity, passed, violations, sample FROM tmp_integrity_report ORDER BY seq;
    DROP TEMPORARY TABLE tmp_integrity_report;
END $$

-- =============================================================================
-- Maintenance post-incident (réservé au rôle ra_payment_maint)
-- =============================================================================
-- Reconstruit la projection des soldes depuis le grand livre.
-- Refuse d'agir si le grand livre lui-même est compromis (C1/C2 en échec) :
-- dans ce cas seule une restauration depuis sauvegarde est légitime (escalade).
CREATE DEFINER = 'ra_owner'@'localhost' PROCEDURE ra_payment.sp_repair_balances(
    IN p_reason TEXT, IN p_incident_id CHAR(36), IN p_dry_run BOOLEAN)
MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
    DECLARE v_locked BIGINT;
    DECLARE v_compromised INT;

    IF p_reason IS NULL OR CHAR_LENGTH(TRIM(p_reason)) < 5 THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = '22023 a meaningful repair reason is required';
    END IF;

    -- Gèle toute écriture de solde pendant la réparation (lectures toujours possibles).
    SELECT COUNT(*) INTO v_locked FROM ra_payment.account_balances FOR UPDATE;

    CALL ra_payment.sp_integrity_fill(300);
    SELECT COUNT(*) INTO v_compromised FROM tmp_integrity_report
     WHERE check_code IN ('LEDGER_HASH_CHAIN', 'LEDGER_RUNNING_BALANCE') AND NOT passed;
    DROP TEMPORARY TABLE tmp_integrity_report;
    IF v_compromised > 0 THEN
        SIGNAL SQLSTATE 'RA012'
            SET MESSAGE_TEXT = 'RA012 ledger is compromised: automatic repair refused, restore from backup required';
    END IF;

    CREATE OR REPLACE TEMPORARY TABLE tmp_repair_tail AS
    SELECT b.account_id, b.available_minor, b.entry_count, b.last_entry_hash,
           t.expected_balance_minor, t.expected_entry_count, t.expected_last_hash
      FROM ra_payment.account_balances b
      JOIN ra_payment.v_account_ledger_tail t ON t.account_id = b.account_id
     WHERE b.available_minor <> t.expected_balance_minor
        OR b.entry_count <> t.expected_entry_count
        OR b.last_entry_hash <> t.expected_last_hash;

    CREATE OR REPLACE TEMPORARY TABLE tmp_repairs AS
    SELECT account_id AS repaired_account_id, field_name, previous_value, corrected_value FROM (
        SELECT account_id, 1 AS ord, 'available_minor' AS field_name,
               CAST(available_minor AS CHAR) AS previous_value, CAST(expected_balance_minor AS CHAR) AS corrected_value
          FROM tmp_repair_tail WHERE available_minor <> expected_balance_minor
        UNION ALL
        SELECT account_id, 2, 'entry_count', CAST(entry_count AS CHAR), CAST(expected_entry_count AS CHAR)
          FROM tmp_repair_tail WHERE entry_count <> expected_entry_count
        UNION ALL
        SELECT account_id, 3, 'last_entry_hash', LOWER(HEX(last_entry_hash)), LOWER(HEX(expected_last_hash))
          FROM tmp_repair_tail WHERE last_entry_hash <> expected_last_hash
    ) fields ORDER BY account_id, ord;

    IF NOT p_dry_run THEN
        INSERT INTO ra_payment.integrity_repairs (account_id, field_name, previous_value, corrected_value, reason, incident_id, db_user)
        SELECT repaired_account_id, field_name, previous_value, corrected_value, LEFT(p_reason, 256), p_incident_id, SESSION_USER()
          FROM tmp_repairs;

        UPDATE ra_payment.account_balances b
          JOIN tmp_repair_tail t ON t.account_id = b.account_id
           SET b.available_minor = t.expected_balance_minor,
               b.entry_count     = t.expected_entry_count,
               b.last_entry_hash = t.expected_last_hash,
               b.version         = b.version + 1,
               b.updated_at      = SYSDATE(6);
    END IF;

    SELECT repaired_account_id, field_name, previous_value, corrected_value FROM tmp_repairs;
    DROP TEMPORARY TABLE tmp_repairs;
    DROP TEMPORARY TABLE tmp_repair_tail;
END $$

-- Purge des transactions bloquées en vol : passage en FAILED (jamais de suppression).
CREATE DEFINER = 'ra_owner'@'localhost' PROCEDURE ra_payment.sp_fail_stale_transactions(
    IN p_older_than_seconds INT, IN p_reason TEXT, IN p_incident_id CHAR(36))
MODIFIES SQL DATA SQL SECURITY DEFINER
BEGIN
    IF p_older_than_seconds IS NULL OR p_older_than_seconds < 60 THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = '22023 p_older_than_seconds must be >= 60';
    END IF;
    IF p_reason IS NULL OR CHAR_LENGTH(TRIM(p_reason)) < 5 THEN
        SIGNAL SQLSTATE '22023' SET MESSAGE_TEXT = '22023 a meaningful purge reason is required';
    END IF;

    UPDATE ra_payment.transactions
       SET status = 'FAILED',
           failure_code = 'STALE_PURGED',
           failure_reason = LEFT(CONCAT(p_reason, ' (incident=', COALESCE(p_incident_id, 'n/a'), ')'), 512)
     WHERE status IN ('PENDING', 'VALIDATED')
       AND created_at < SYSDATE(6) - INTERVAL p_older_than_seconds SECOND;
    SELECT ROW_COUNT() AS purged;
END $$

DELIMITER ;

-- =============================================================================
-- Privilèges
-- =============================================================================
-- ra_payment_app : runtime métier. Ni UPDATE de solde, ni INSERT au grand livre :
-- toute écriture financière passe par sp_execute_transaction.
GRANT SELECT ON ra_payment.currencies TO ra_payment_app_role;
GRANT SELECT ON ra_payment.accounts TO ra_payment_app_role;
GRANT SELECT ON ra_payment.account_balances TO ra_payment_app_role;
GRANT SELECT, INSERT, UPDATE (status, failure_code, failure_reason) ON ra_payment.transactions TO ra_payment_app_role;
GRANT SELECT ON ra_payment.transaction_status_history TO ra_payment_app_role;
GRANT SELECT ON ra_payment.ledger_entries TO ra_payment_app_role;
GRANT SELECT ON ra_payment.runtime_flags TO ra_payment_app_role;
GRANT SELECT, INSERT ON ra_payment.integrity_reports TO ra_payment_app_role;
GRANT SELECT, INSERT, DELETE ON ra_payment.event_outbox TO ra_payment_app_role;
GRANT EXECUTE ON PROCEDURE ra_payment.sp_execute_transaction TO ra_payment_app_role;
GRANT EXECUTE ON PROCEDURE ra_payment.sp_integrity_report TO ra_payment_app_role;

-- ra_payment_maint : actions de remédiation déclenchées via /admin (connexion dédiée).
GRANT SELECT ON ra_payment.* TO ra_payment_maint_role;
GRANT INSERT, UPDATE (value, reason, updated_by, incident_id) ON ra_payment.runtime_flags TO ra_payment_maint_role;
GRANT INSERT ON ra_payment.integrity_reports TO ra_payment_maint_role;
GRANT UPDATE (status) ON ra_payment.accounts TO ra_payment_maint_role;
GRANT EXECUTE ON PROCEDURE ra_payment.sp_integrity_report TO ra_payment_maint_role;
GRANT EXECUTE ON PROCEDURE ra_payment.sp_repair_balances TO ra_payment_maint_role;
GRANT EXECUTE ON PROCEDURE ra_payment.sp_fail_stale_transactions TO ra_payment_maint_role;
