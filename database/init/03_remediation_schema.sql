-- =============================================================================
-- PROJECT RESILIENCE-ALPHA — 03 : base `ra_remediation` (propriété : remediation-engine)
-- -----------------------------------------------------------------------------
-- Alertes reçues, incidents (machine à états), playbooks, exécutions pas-à-pas,
-- vérifications synthétiques post-reprise, échantillons de santé et chronologie
-- des phases système (NOMINAL / DÉGRADÉ / CRITIQUE / RÉTABLISSEMENT / RÉTABLI).
--
-- Critère d'acceptation majeur garanti PAR LA BASE :
--   un incident ne peut passer en RESOLVED que si sa DERNIÈRE vérification
--   synthétique de bout en bout est PASSED (SQLSTATE RA203 sinon).
--
-- Codes SQLSTATE (classe RA2xx) :
--   RA201 champ immuable   RA202 transition interdite   RA203 clôture sans vérification
--   RA204 création hors état OPEN                       RA006 table append-only
-- Les index uniques partiels de PostgreSQL sont reproduits par des colonnes
-- générées valant NULL hors du périmètre (NULL n'entre pas en conflit d'unicité).
-- =============================================================================
SET NAMES utf8mb4;
SET time_zone = '+00:00';
SET sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

CREATE DATABASE ra_remediation CHARACTER SET utf8mb4 COLLATE utf8mb4_bin
    COMMENT 'Détection -> décision -> remédiation -> vérification (remediation-engine)';

-- -----------------------------------------------------------------------------
-- Playbooks (catalogue déclaratif ; une seule version active par catégorie)
-- -----------------------------------------------------------------------------
CREATE TABLE ra_remediation.playbooks (
    code                    VARCHAR(64)  NOT NULL PRIMARY KEY,
    version                 INT          NOT NULL DEFAULT 1,
    category                ENUM('SERVICE_UNAVAILABLE', 'PERFORMANCE_DEGRADATION', 'RESOURCE_EXHAUSTION',
                                 'DATA_INTEGRITY_VIOLATION', 'CREDENTIAL_COMPROMISE', 'ANOMALOUS_TRAFFIC',
                                 'FRAUD_PATTERN') NOT NULL,
    title                   VARCHAR(128) NOT NULL,
    description             TEXT         NOT NULL,
    steps                   JSON         NOT NULL,
    post_verification_steps JSON         NOT NULL DEFAULT '[]',
    max_attempts            SMALLINT     NOT NULL DEFAULT 2,
    step_timeout_seconds    INT          NOT NULL DEFAULT 60,
    cooldown_seconds        INT          NOT NULL DEFAULT 60,
    enabled                 BOOLEAN      NOT NULL DEFAULT TRUE,
    updated_at              DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    active_category         VARCHAR(32) AS (IF(enabled, category, NULL)) PERSISTENT,
    CONSTRAINT uq_playbooks_active_category UNIQUE (active_category),
    CONSTRAINT ck_playbook_code     CHECK (code REGEXP '^PB-[A-Z0-9-]{3,60}$'),
    CONSTRAINT ck_playbook_version  CHECK (version > 0),
    CONSTRAINT ck_playbook_steps    CHECK (JSON_TYPE(steps) = 'ARRAY' AND JSON_LENGTH(steps) BETWEEN 1 AND 20),
    CONSTRAINT ck_playbook_post     CHECK (JSON_TYPE(post_verification_steps) = 'ARRAY' AND JSON_LENGTH(post_verification_steps) <= 10),
    CONSTRAINT ck_playbook_attempts CHECK (max_attempts BETWEEN 1 AND 5),
    CONSTRAINT ck_playbook_timeout  CHECK (step_timeout_seconds BETWEEN 5 AND 600),
    CONSTRAINT ck_playbook_cooldown CHECK (cooldown_seconds >= 0)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Incidents
-- -----------------------------------------------------------------------------
CREATE TABLE ra_remediation.incidents (
    id                     CHAR(36) CHARACTER SET ascii NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    fingerprint            CHAR(64)     NOT NULL,
    category               ENUM('SERVICE_UNAVAILABLE', 'PERFORMANCE_DEGRADATION', 'RESOURCE_EXHAUSTION',
                                'DATA_INTEGRITY_VIOLATION', 'CREDENTIAL_COMPROMISE', 'ANOMALOUS_TRAFFIC',
                                'FRAUD_PATTERN') NOT NULL,
    severity               ENUM('INFO', 'WARNING', 'HIGH', 'CRITICAL') NOT NULL,
    status                 ENUM('OPEN', 'TRIAGED', 'REMEDIATING', 'VERIFYING', 'RESOLVED', 'ESCALATED', 'SUPPRESSED')
                           NOT NULL DEFAULT 'OPEN',
    status_reason          VARCHAR(512) NOT NULL DEFAULT 'alert received',
    title                  VARCHAR(200) NOT NULL,
    target_service         VARCHAR(64)  NOT NULL,
    target_principal_id    CHAR(36) CHARACTER SET ascii,
    target_account_id      CHAR(36) CHARACTER SET ascii,
    playbook_code          VARCHAR(64),
    attempt_count          SMALLINT     NOT NULL DEFAULT 0,
    alert_count            INT          NOT NULL DEFAULT 1,
    resolution             VARCHAR(16),
    last_error             VARCHAR(1024),
    opened_at              DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    remediation_started_at DATETIME(6),
    verified_at            DATETIME(6),
    closed_at              DATETIME(6),
    updated_at             DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    -- Déduplication : un seul incident ouvert par empreinte (RTRIM : MariaDB refuse une
    -- colonne CHAR brute dans une colonne générée indexée, cf. PAD_CHAR_TO_FULL_LENGTH).
    open_fingerprint       VARCHAR(64) AS (IF(status IN ('RESOLVED', 'SUPPRESSED'), NULL, RTRIM(fingerprint))) PERSISTENT,
    CONSTRAINT uq_incidents_open_fingerprint UNIQUE (open_fingerprint),
    INDEX ix_incidents_status_opened (status, opened_at),
    INDEX ix_incidents_opened        (opened_at, id),
    INDEX ix_incidents_target_closed (target_service, closed_at),
    CONSTRAINT fk_incidents_playbook FOREIGN KEY (playbook_code) REFERENCES ra_remediation.playbooks (code),
    CONSTRAINT ck_incident_service     CHECK (target_service IN ('auth-service', 'payment-api', 'database', 'remediation-engine', 'frontend-dashboard')),
    CONSTRAINT ck_incident_fingerprint CHECK (fingerprint REGEXP '^[0-9a-f]{64}$'),
    CONSTRAINT ck_incident_attempts    CHECK (attempt_count >= 0),
    CONSTRAINT ck_incident_alerts      CHECK (alert_count >= 1),
    CONSTRAINT ck_incident_resolution  CHECK (resolution IS NULL OR resolution IN ('AUTOMATIC', 'MANUAL', 'SUPPRESSED')),
    CONSTRAINT ck_incident_closed      CHECK ((status IN ('RESOLVED', 'SUPPRESSED')) = (closed_at IS NOT NULL)),
    CONSTRAINT ck_incident_resolved    CHECK ((status IN ('RESOLVED', 'SUPPRESSED')) = (resolution IS NOT NULL)),
    CONSTRAINT ck_incident_verified    CHECK (status <> 'RESOLVED' OR verified_at IS NOT NULL)
) ENGINE = InnoDB;

CREATE TABLE ra_remediation.incident_transitions (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    incident_id CHAR(36) CHARACTER SET ascii NOT NULL,
    from_status ENUM('OPEN', 'TRIAGED', 'REMEDIATING', 'VERIFYING', 'RESOLVED', 'ESCALATED', 'SUPPRESSED'),
    to_status   ENUM('OPEN', 'TRIAGED', 'REMEDIATING', 'VERIFYING', 'RESOLVED', 'ESCALATED', 'SUPPRESSED') NOT NULL,
    reason      VARCHAR(512) NOT NULL,
    occurred_at DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    INDEX ix_incident_transitions_incident (incident_id, id),
    CONSTRAINT fk_transitions_incident FOREIGN KEY (incident_id) REFERENCES ra_remediation.incidents (id)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Alertes (idempotence webhook : unicité source + external_id)
-- -----------------------------------------------------------------------------
CREATE TABLE ra_remediation.alerts (
    id             CHAR(36) CHARACTER SET ascii NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    source         VARCHAR(64)  NOT NULL,
    external_id    VARCHAR(128) NOT NULL,
    fingerprint    CHAR(64)     NOT NULL,
    category       ENUM('SERVICE_UNAVAILABLE', 'PERFORMANCE_DEGRADATION', 'RESOURCE_EXHAUSTION',
                        'DATA_INTEGRITY_VIOLATION', 'CREDENTIAL_COMPROMISE', 'ANOMALOUS_TRAFFIC',
                        'FRAUD_PATTERN') NOT NULL,
    severity       ENUM('INFO', 'WARNING', 'HIGH', 'CRITICAL') NOT NULL,
    confidence     DECIMAL(4, 3),
    title          VARCHAR(200) NOT NULL,
    target_service VARCHAR(64)  NOT NULL,
    detected_at    DATETIME(6)  NOT NULL,
    received_at    DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    payload        JSON         NOT NULL,
    incident_id    CHAR(36) CHARACTER SET ascii,
    CONSTRAINT uq_alerts_source_external UNIQUE (source, external_id),
    INDEX ix_alerts_incident (incident_id, received_at),
    INDEX ix_alerts_received (received_at),
    CONSTRAINT fk_alerts_incident FOREIGN KEY (incident_id) REFERENCES ra_remediation.incidents (id),
    CONSTRAINT ck_alert_service     CHECK (target_service IN ('auth-service', 'payment-api', 'database', 'remediation-engine', 'frontend-dashboard')),
    CONSTRAINT ck_alert_source      CHECK (source REGEXP '^[a-z0-9][a-z0-9-]{1,63}$'),
    CONSTRAINT ck_alert_fingerprint CHECK (fingerprint REGEXP '^[0-9a-f]{64}$'),
    CONSTRAINT ck_alert_confidence  CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    CONSTRAINT ck_alert_payload     CHECK (LENGTH(payload) <= 65536)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Exécutions de playbooks & étapes
-- -----------------------------------------------------------------------------
CREATE TABLE ra_remediation.executions (
    id               CHAR(36) CHARACTER SET ascii NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    incident_id      CHAR(36) CHARACTER SET ascii NOT NULL,
    playbook_code    VARCHAR(64)  NOT NULL,
    playbook_version INT          NOT NULL,
    attempt          SMALLINT     NOT NULL,
    status           ENUM('RUNNING', 'SUCCEEDED', 'FAILED', 'ABORTED') NOT NULL DEFAULT 'RUNNING',
    started_at       DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    finished_at      DATETIME(6),
    error            VARCHAR(1024),
    running_incident VARCHAR(36) CHARACTER SET ascii AS (IF(status = 'RUNNING', RTRIM(incident_id), NULL)) PERSISTENT,
    CONSTRAINT uq_executions_attempt UNIQUE (incident_id, attempt),
    CONSTRAINT uq_executions_one_running UNIQUE (running_incident),
    INDEX ix_executions_started (started_at),
    CONSTRAINT fk_executions_incident FOREIGN KEY (incident_id) REFERENCES ra_remediation.incidents (id),
    CONSTRAINT fk_executions_playbook FOREIGN KEY (playbook_code) REFERENCES ra_remediation.playbooks (code),
    CONSTRAINT ck_execution_attempt  CHECK (attempt >= 1),
    CONSTRAINT ck_execution_finished CHECK ((status = 'RUNNING') = (finished_at IS NULL))
) ENGINE = InnoDB;

CREATE TABLE ra_remediation.execution_steps (
    id           BIGINT        NOT NULL AUTO_INCREMENT PRIMARY KEY,
    execution_id CHAR(36) CHARACTER SET ascii NOT NULL,
    phase        VARCHAR(24)   NOT NULL,
    seq          SMALLINT      NOT NULL,
    action       VARCHAR(64)   NOT NULL,
    target       VARCHAR(128),
    params       JSON          NOT NULL DEFAULT '{}',
    status       ENUM('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'SKIPPED') NOT NULL DEFAULT 'PENDING',
    started_at   DATETIME(6),
    finished_at  DATETIME(6),
    duration_ms  INT,
    output       JSON,
    error        VARCHAR(1024),
    CONSTRAINT uq_execution_steps_seq UNIQUE (execution_id, phase, seq),
    CONSTRAINT fk_steps_execution FOREIGN KEY (execution_id) REFERENCES ra_remediation.executions (id),
    CONSTRAINT ck_step_phase    CHECK (phase IN ('REMEDIATION', 'POST_VERIFICATION')),
    CONSTRAINT ck_step_seq      CHECK (seq >= 1),
    CONSTRAINT ck_step_action   CHECK (action REGEXP '^[a-z]+\\.[a-z_]+$'),
    CONSTRAINT ck_step_duration CHECK (duration_ms IS NULL OR duration_ms >= 0)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Vérifications synthétiques post-reprise (Synthetic Transaction Monitoring)
-- -----------------------------------------------------------------------------
CREATE TABLE ra_remediation.verification_runs (
    id                        CHAR(36) CHARACTER SET ascii NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    incident_id               CHAR(36) CHARACTER SET ascii,
    execution_id              CHAR(36) CHARACTER SET ascii,
    trigger_source            VARCHAR(16) NOT NULL,
    status                    ENUM('RUNNING', 'PASSED', 'FAILED') NOT NULL DEFAULT 'RUNNING',
    started_at                DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    finished_at               DATETIME(6),
    failed_check              VARCHAR(64),
    synthetic_transaction_ids JSON        NOT NULL DEFAULT '[]',
    INDEX ix_verification_incident (incident_id, started_at),
    INDEX ix_verification_started  (started_at),
    CONSTRAINT fk_verification_incident  FOREIGN KEY (incident_id)  REFERENCES ra_remediation.incidents (id),
    CONSTRAINT fk_verification_execution FOREIGN KEY (execution_id) REFERENCES ra_remediation.executions (id),
    CONSTRAINT ck_verification_trigger  CHECK (trigger_source IN ('REMEDIATION', 'MANUAL', 'SCHEDULED')),
    CONSTRAINT ck_verification_finished CHECK ((status = 'RUNNING') = (finished_at IS NULL)),
    CONSTRAINT ck_verification_failed   CHECK ((status = 'FAILED') = (failed_check IS NOT NULL)),
    CONSTRAINT ck_verification_incident CHECK (trigger_source = 'SCHEDULED' OR incident_id IS NOT NULL),
    CONSTRAINT ck_verification_tx_ids   CHECK (JSON_TYPE(synthetic_transaction_ids) = 'ARRAY')
) ENGINE = InnoDB;

CREATE TABLE ra_remediation.verification_checks (
    id          BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    run_id      CHAR(36) CHARACTER SET ascii NOT NULL,
    seq         SMALLINT    NOT NULL,
    check_code  VARCHAR(64) NOT NULL,
    passed      BOOLEAN     NOT NULL,
    latency_ms  INT,
    detail      JSON        NOT NULL DEFAULT '{}',
    executed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_verification_checks_seq UNIQUE (run_id, seq),
    CONSTRAINT fk_checks_run FOREIGN KEY (run_id) REFERENCES ra_remediation.verification_runs (id),
    CONSTRAINT ck_check_code    CHECK (check_code REGEXP '^[A-Z][A-Z0-9_]+$'),
    CONSTRAINT ck_check_latency CHECK (latency_ms IS NULL OR latency_ms >= 0)
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Santé des services & chronologie des phases (vue NOC Avant / Pendant / Après)
-- -----------------------------------------------------------------------------
CREATE TABLE ra_remediation.service_health_samples (
    id          BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    service     VARCHAR(64) NOT NULL,
    status      ENUM('UP', 'DEGRADED', 'DOWN', 'UNKNOWN') NOT NULL,
    latency_ms  INT,
    http_status SMALLINT,
    observed_at DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    details     JSON        NOT NULL DEFAULT '{}',
    INDEX ix_health_service_observed (service, observed_at),
    INDEX ix_health_observed         (observed_at),
    CONSTRAINT ck_health_service CHECK (service IN ('auth-service', 'payment-api', 'database', 'remediation-engine', 'frontend-dashboard')),
    CONSTRAINT ck_health_latency CHECK (latency_ms IS NULL OR latency_ms >= 0)
) ENGINE = InnoDB;

CREATE TABLE ra_remediation.phase_history (
    id          BIGINT       NOT NULL AUTO_INCREMENT PRIMARY KEY,
    phase       ENUM('NOMINAL', 'DEGRADED', 'CRITICAL', 'RECOVERING', 'RESTORED') NOT NULL,
    entered_at  DATETIME(6)  NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    incident_id CHAR(36) CHARACTER SET ascii,
    reason      VARCHAR(256) NOT NULL,
    INDEX ix_phase_history_entered (entered_at),
    CONSTRAINT fk_phase_incident FOREIGN KEY (incident_id) REFERENCES ra_remediation.incidents (id)
) ENGINE = InnoDB;

-- =============================================================================
-- Déclencheurs (exécutés avec les droits de ra_owner)
-- =============================================================================
DELIMITER $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_incidents_before_insert
BEFORE INSERT ON ra_remediation.incidents FOR EACH ROW
BEGIN
    IF NEW.status <> 'OPEN' THEN
        SIGNAL SQLSTATE 'RA204' SET MESSAGE_TEXT = 'RA204 an incident must be created in OPEN status';
    END IF;
    SET NEW.opened_at = SYSDATE(6);
    SET NEW.updated_at = NEW.opened_at;
    SET NEW.remediation_started_at = NULL;
    SET NEW.verified_at = NULL;
    SET NEW.closed_at = NULL;
    SET NEW.resolution = NULL;
END $$

-- Machine à états des incidents + garde du critère de vérification post-reprise.
CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_incidents_before_update
BEFORE UPDATE ON ra_remediation.incidents FOR EACH ROW
BEGIN
    DECLARE v_last_status   VARCHAR(16);
    DECLARE v_last_finished DATETIME(6);
    DECLARE v_msg           VARCHAR(128);

    IF NOT (NEW.id <=> OLD.id AND NEW.fingerprint <=> OLD.fingerprint
            AND NEW.category <=> OLD.category AND NEW.opened_at <=> OLD.opened_at) THEN
        SET v_msg = CONCAT('RA201 immutable incident fields modified on ', OLD.id);
        SIGNAL SQLSTATE 'RA201' SET MESSAGE_TEXT = v_msg;
    END IF;

    -- Champs de cycle de vie posés exclusivement par la base.
    SET NEW.remediation_started_at = OLD.remediation_started_at;
    SET NEW.verified_at = OLD.verified_at;
    SET NEW.closed_at = OLD.closed_at;

    IF NOT (NEW.status <=> OLD.status) THEN
        IF NOT (
               (OLD.status = 'OPEN'        AND NEW.status IN ('TRIAGED', 'SUPPRESSED', 'ESCALATED'))
            OR (OLD.status = 'TRIAGED'     AND NEW.status IN ('REMEDIATING', 'SUPPRESSED', 'ESCALATED'))
            OR (OLD.status = 'REMEDIATING' AND NEW.status IN ('VERIFYING', 'ESCALATED'))
            OR (OLD.status = 'VERIFYING'   AND NEW.status IN ('RESOLVED', 'REMEDIATING', 'ESCALATED'))
            OR (OLD.status = 'ESCALATED'   AND NEW.status IN ('REMEDIATING', 'VERIFYING'))
        ) THEN
            SET v_msg = CONCAT('RA202 illegal incident transition ', OLD.status, ' -> ', NEW.status, ' on ', OLD.id);
            SIGNAL SQLSTATE 'RA202' SET MESSAGE_TEXT = v_msg;
        END IF;

        IF NEW.status = 'REMEDIATING' THEN
            SET NEW.remediation_started_at = COALESCE(OLD.remediation_started_at, SYSDATE(6));
        ELSEIF NEW.status = 'RESOLVED' THEN
            SELECT vr.status, vr.finished_at INTO v_last_status, v_last_finished
              FROM ra_remediation.verification_runs vr
             WHERE vr.incident_id = NEW.id
             ORDER BY vr.started_at DESC, vr.id DESC
             LIMIT 1;
            IF NOT (v_last_status <=> 'PASSED') THEN
                SET v_msg = CONCAT('RA203 incident ', NEW.id, ' cannot be RESOLVED: last synthetic verification is ',
                                   COALESCE(v_last_status, 'missing'));
                SIGNAL SQLSTATE 'RA203' SET MESSAGE_TEXT = v_msg;
            END IF;
            SET NEW.verified_at = v_last_finished;
            SET NEW.closed_at = SYSDATE(6);
            SET NEW.resolution = COALESCE(NEW.resolution, 'AUTOMATIC');
        ELSEIF NEW.status = 'SUPPRESSED' THEN
            SET NEW.closed_at = SYSDATE(6);
            SET NEW.resolution = 'SUPPRESSED';
        END IF;
    ELSEIF OLD.status IN ('RESOLVED', 'SUPPRESSED') THEN
        SET v_msg = CONCAT('RA201 closed incident ', OLD.id, ' is immutable');
        SIGNAL SQLSTATE 'RA201' SET MESSAGE_TEXT = v_msg;
    END IF;

    SET NEW.updated_at = SYSDATE(6);
END $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_incidents_transition_insert
AFTER INSERT ON ra_remediation.incidents FOR EACH ROW
    INSERT INTO ra_remediation.incident_transitions (incident_id, from_status, to_status, reason, occurred_at)
    VALUES (NEW.id, NULL, NEW.status, NEW.status_reason, SYSDATE(6)) $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_incidents_transition_update
AFTER UPDATE ON ra_remediation.incidents FOR EACH ROW
BEGIN
    IF NOT (NEW.status <=> OLD.status) THEN
        INSERT INTO ra_remediation.incident_transitions (incident_id, from_status, to_status, reason, occurred_at)
        VALUES (NEW.id, OLD.status, NEW.status, NEW.status_reason, SYSDATE(6));
    END IF;
END $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_incidents_no_delete
BEFORE DELETE ON ra_remediation.incidents FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_remediation.incidents is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_incident_transitions_no_update
BEFORE UPDATE ON ra_remediation.incident_transitions FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_remediation.incident_transitions is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_incident_transitions_no_delete
BEFORE DELETE ON ra_remediation.incident_transitions FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_remediation.incident_transitions is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_verification_checks_no_update
BEFORE UPDATE ON ra_remediation.verification_checks FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_remediation.verification_checks is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_verification_checks_no_delete
BEFORE DELETE ON ra_remediation.verification_checks FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_remediation.verification_checks is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_phase_history_no_update
BEFORE UPDATE ON ra_remediation.phase_history FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_remediation.phase_history is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_remediation.trg_phase_history_no_delete
BEFORE DELETE ON ra_remediation.phase_history FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_remediation.phase_history is append-only' $$

DELIMITER ;

-- =============================================================================
-- Privilèges : aucun accès aux bases ra_auth / ra_payment (actions via API uniquement)
-- =============================================================================
GRANT SELECT ON ra_remediation.* TO ra_remediation_app_role;
GRANT UPDATE (enabled) ON ra_remediation.playbooks TO ra_remediation_app_role;
GRANT INSERT, UPDATE (severity, status, status_reason, title, playbook_code, attempt_count, alert_count, resolution, last_error)
    ON ra_remediation.incidents TO ra_remediation_app_role;
GRANT INSERT, UPDATE (incident_id) ON ra_remediation.alerts TO ra_remediation_app_role;
GRANT INSERT, UPDATE (status, finished_at, error) ON ra_remediation.executions TO ra_remediation_app_role;
GRANT INSERT, UPDATE (status, started_at, finished_at, duration_ms, output, error) ON ra_remediation.execution_steps TO ra_remediation_app_role;
GRANT INSERT, UPDATE (status, finished_at, failed_check, synthetic_transaction_ids) ON ra_remediation.verification_runs TO ra_remediation_app_role;
GRANT INSERT ON ra_remediation.verification_checks TO ra_remediation_app_role;
GRANT INSERT, DELETE ON ra_remediation.service_health_samples TO ra_remediation_app_role;
GRANT INSERT ON ra_remediation.phase_history TO ra_remediation_app_role;
