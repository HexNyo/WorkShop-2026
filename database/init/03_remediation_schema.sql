-- =============================================================================
-- PROJECT RESILIENCE-ALPHA — 03 : schéma `remediation` (propriété : remediation-engine)
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
-- =============================================================================
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL ROLE ra_owner;

CREATE SCHEMA remediation;
REVOKE ALL ON SCHEMA remediation FROM PUBLIC;
COMMENT ON SCHEMA remediation IS 'Détection -> décision -> remédiation -> vérification (remediation-engine)';

CREATE TYPE remediation.severity            AS ENUM ('INFO', 'WARNING', 'HIGH', 'CRITICAL');
CREATE TYPE remediation.alert_category      AS ENUM ('SERVICE_UNAVAILABLE', 'PERFORMANCE_DEGRADATION', 'RESOURCE_EXHAUSTION',
                                                     'DATA_INTEGRITY_VIOLATION', 'CREDENTIAL_COMPROMISE', 'ANOMALOUS_TRAFFIC',
                                                     'FRAUD_PATTERN');
CREATE TYPE remediation.incident_status     AS ENUM ('OPEN', 'TRIAGED', 'REMEDIATING', 'VERIFYING', 'RESOLVED', 'ESCALATED', 'SUPPRESSED');
CREATE TYPE remediation.execution_status    AS ENUM ('RUNNING', 'SUCCEEDED', 'FAILED', 'ABORTED');
CREATE TYPE remediation.step_status         AS ENUM ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'SKIPPED');
CREATE TYPE remediation.verification_status AS ENUM ('RUNNING', 'PASSED', 'FAILED');
CREATE TYPE remediation.service_status      AS ENUM ('UP', 'DEGRADED', 'DOWN', 'UNKNOWN');
CREATE TYPE remediation.system_phase        AS ENUM ('NOMINAL', 'DEGRADED', 'CRITICAL', 'RECOVERING', 'RESTORED');

-- Domaine des services supervisés (référentiel fermé).
CREATE DOMAIN remediation.service_name AS varchar(64)
    CHECK (VALUE IN ('auth-service', 'payment-api', 'database', 'remediation-engine', 'frontend-dashboard'));

-- -----------------------------------------------------------------------------
-- Playbooks (catalogue déclaratif ; une seule version active par catégorie)
-- -----------------------------------------------------------------------------
CREATE TABLE remediation.playbooks (
    code                    varchar(64)                    PRIMARY KEY,
    version                 integer                        NOT NULL DEFAULT 1,
    category                remediation.alert_category     NOT NULL,
    title                   varchar(128)                   NOT NULL,
    description             text                           NOT NULL,
    steps                   jsonb                          NOT NULL,
    post_verification_steps jsonb                          NOT NULL DEFAULT '[]'::jsonb,
    max_attempts            smallint                       NOT NULL DEFAULT 2,
    step_timeout_seconds    integer                        NOT NULL DEFAULT 60,
    cooldown_seconds        integer                        NOT NULL DEFAULT 60,
    enabled                 boolean                        NOT NULL DEFAULT true,
    updated_at              timestamptz                    NOT NULL DEFAULT now(),
    CONSTRAINT ck_playbook_code     CHECK (code ~ '^PB-[A-Z0-9-]{3,60}$'),
    CONSTRAINT ck_playbook_version  CHECK (version > 0),
    CONSTRAINT ck_playbook_steps    CHECK (jsonb_typeof(steps) = 'array' AND jsonb_array_length(steps) BETWEEN 1 AND 20),
    CONSTRAINT ck_playbook_post     CHECK (jsonb_typeof(post_verification_steps) = 'array' AND jsonb_array_length(post_verification_steps) <= 10),
    CONSTRAINT ck_playbook_attempts CHECK (max_attempts BETWEEN 1 AND 5),
    CONSTRAINT ck_playbook_timeout  CHECK (step_timeout_seconds BETWEEN 5 AND 600),
    CONSTRAINT ck_playbook_cooldown CHECK (cooldown_seconds >= 0)
);
CREATE UNIQUE INDEX uq_playbooks_active_category ON remediation.playbooks (category) WHERE enabled;

-- -----------------------------------------------------------------------------
-- Incidents
-- -----------------------------------------------------------------------------
CREATE TABLE remediation.incidents (
    id                     uuid                        PRIMARY KEY DEFAULT gen_random_uuid(),
    fingerprint            char(64)                    NOT NULL,
    category               remediation.alert_category  NOT NULL,
    severity               remediation.severity        NOT NULL,
    status                 remediation.incident_status NOT NULL DEFAULT 'OPEN',
    status_reason          varchar(512)                NOT NULL DEFAULT 'alert received',
    title                  varchar(200)                NOT NULL,
    target_service         remediation.service_name    NOT NULL,
    target_principal_id    uuid,
    target_account_id      uuid,
    playbook_code          varchar(64)                 REFERENCES remediation.playbooks(code),
    attempt_count          smallint                    NOT NULL DEFAULT 0,
    alert_count            integer                     NOT NULL DEFAULT 1,
    resolution             varchar(16),
    last_error             varchar(1024),
    opened_at              timestamptz                 NOT NULL DEFAULT clock_timestamp(),
    remediation_started_at timestamptz,
    verified_at            timestamptz,
    closed_at              timestamptz,
    updated_at             timestamptz                 NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT ck_incident_fingerprint CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_incident_attempts    CHECK (attempt_count >= 0),
    CONSTRAINT ck_incident_alerts      CHECK (alert_count >= 1),
    CONSTRAINT ck_incident_resolution  CHECK (resolution IS NULL OR resolution IN ('AUTOMATIC', 'MANUAL', 'SUPPRESSED')),
    CONSTRAINT ck_incident_closed      CHECK ((status IN ('RESOLVED', 'SUPPRESSED')) = (closed_at IS NOT NULL)),
    CONSTRAINT ck_incident_resolved    CHECK ((status IN ('RESOLVED', 'SUPPRESSED')) = (resolution IS NOT NULL)),
    CONSTRAINT ck_incident_verified    CHECK (status <> 'RESOLVED' OR verified_at IS NOT NULL)
);
-- Déduplication : un seul incident ouvert par empreinte.
CREATE UNIQUE INDEX uq_incidents_open_fingerprint ON remediation.incidents (fingerprint)
    WHERE status NOT IN ('RESOLVED', 'SUPPRESSED');
CREATE INDEX ix_incidents_status_opened ON remediation.incidents (status, opened_at DESC);
CREATE INDEX ix_incidents_opened        ON remediation.incidents (opened_at DESC, id DESC);
CREATE INDEX ix_incidents_target_closed ON remediation.incidents (target_service, closed_at DESC);

CREATE TABLE remediation.incident_transitions (
    id          bigint                      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id uuid                        NOT NULL REFERENCES remediation.incidents(id),
    from_status remediation.incident_status,
    to_status   remediation.incident_status NOT NULL,
    reason      varchar(512)                NOT NULL,
    occurred_at timestamptz                 NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX ix_incident_transitions_incident ON remediation.incident_transitions (incident_id, id);

-- -----------------------------------------------------------------------------
-- Alertes (idempotence webhook : unicité source + external_id)
-- -----------------------------------------------------------------------------
CREATE TABLE remediation.alerts (
    id             uuid                       PRIMARY KEY DEFAULT gen_random_uuid(),
    source         varchar(64)                NOT NULL,
    external_id    varchar(128)               NOT NULL,
    fingerprint    char(64)                   NOT NULL,
    category       remediation.alert_category NOT NULL,
    severity       remediation.severity       NOT NULL,
    confidence     numeric(4,3),
    title          varchar(200)               NOT NULL,
    target_service remediation.service_name   NOT NULL,
    detected_at    timestamptz                NOT NULL,
    received_at    timestamptz                NOT NULL DEFAULT clock_timestamp(),
    payload        jsonb                      NOT NULL,
    incident_id    uuid                       REFERENCES remediation.incidents(id),
    CONSTRAINT uq_alerts_source_external UNIQUE (source, external_id),
    CONSTRAINT ck_alert_source      CHECK (source ~ '^[a-z0-9][a-z0-9-]{1,63}$'),
    CONSTRAINT ck_alert_fingerprint CHECK (fingerprint ~ '^[0-9a-f]{64}$'),
    CONSTRAINT ck_alert_confidence  CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 1),
    CONSTRAINT ck_alert_payload     CHECK (pg_column_size(payload) <= 65536)
);
CREATE INDEX ix_alerts_incident ON remediation.alerts (incident_id, received_at);
CREATE INDEX ix_alerts_received ON remediation.alerts (received_at DESC);

-- -----------------------------------------------------------------------------
-- Exécutions de playbooks & étapes
-- -----------------------------------------------------------------------------
CREATE TABLE remediation.executions (
    id               uuid                         PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id      uuid                         NOT NULL REFERENCES remediation.incidents(id),
    playbook_code    varchar(64)                  NOT NULL REFERENCES remediation.playbooks(code),
    playbook_version integer                      NOT NULL,
    attempt          smallint                     NOT NULL,
    status           remediation.execution_status NOT NULL DEFAULT 'RUNNING',
    started_at       timestamptz                  NOT NULL DEFAULT clock_timestamp(),
    finished_at      timestamptz,
    error            varchar(1024),
    CONSTRAINT uq_executions_attempt UNIQUE (incident_id, attempt),
    CONSTRAINT ck_execution_attempt  CHECK (attempt >= 1),
    CONSTRAINT ck_execution_finished CHECK ((status = 'RUNNING') = (finished_at IS NULL))
);
CREATE UNIQUE INDEX uq_executions_one_running ON remediation.executions (incident_id) WHERE status = 'RUNNING';
CREATE INDEX ix_executions_started ON remediation.executions (started_at DESC);

CREATE TABLE remediation.execution_steps (
    id           bigint                  GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    execution_id uuid                    NOT NULL REFERENCES remediation.executions(id),
    phase        varchar(24)             NOT NULL,
    seq          smallint                NOT NULL,
    action       varchar(64)             NOT NULL,
    target       varchar(128),
    params       jsonb                   NOT NULL DEFAULT '{}'::jsonb,
    status       remediation.step_status NOT NULL DEFAULT 'PENDING',
    started_at   timestamptz,
    finished_at  timestamptz,
    duration_ms  integer,
    output       jsonb,
    error        varchar(1024),
    CONSTRAINT uq_execution_steps_seq UNIQUE (execution_id, phase, seq),
    CONSTRAINT ck_step_phase    CHECK (phase IN ('REMEDIATION', 'POST_VERIFICATION')),
    CONSTRAINT ck_step_seq      CHECK (seq >= 1),
    CONSTRAINT ck_step_action   CHECK (action ~ '^[a-z]+\.[a-z_]+$'),
    CONSTRAINT ck_step_duration CHECK (duration_ms IS NULL OR duration_ms >= 0)
);

-- -----------------------------------------------------------------------------
-- Vérifications synthétiques post-reprise (Synthetic Transaction Monitoring)
-- -----------------------------------------------------------------------------
CREATE TABLE remediation.verification_runs (
    id                        uuid                            PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_id               uuid                            REFERENCES remediation.incidents(id),
    execution_id              uuid                            REFERENCES remediation.executions(id),
    trigger_source            varchar(16)                     NOT NULL,
    status                    remediation.verification_status NOT NULL DEFAULT 'RUNNING',
    started_at                timestamptz                     NOT NULL DEFAULT clock_timestamp(),
    finished_at               timestamptz,
    failed_check              varchar(64),
    synthetic_transaction_ids uuid[]                          NOT NULL DEFAULT '{}',
    CONSTRAINT ck_verification_trigger  CHECK (trigger_source IN ('REMEDIATION', 'MANUAL', 'SCHEDULED')),
    CONSTRAINT ck_verification_finished CHECK ((status = 'RUNNING') = (finished_at IS NULL)),
    CONSTRAINT ck_verification_failed   CHECK ((status = 'FAILED') = (failed_check IS NOT NULL)),
    CONSTRAINT ck_verification_incident CHECK (trigger_source = 'SCHEDULED' OR incident_id IS NOT NULL)
);
CREATE INDEX ix_verification_incident ON remediation.verification_runs (incident_id, started_at DESC);
CREATE INDEX ix_verification_started  ON remediation.verification_runs (started_at DESC);

CREATE TABLE remediation.verification_checks (
    id          bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    run_id      uuid        NOT NULL REFERENCES remediation.verification_runs(id),
    seq         smallint    NOT NULL,
    check_code  varchar(64) NOT NULL,
    passed      boolean     NOT NULL,
    latency_ms  integer,
    detail      jsonb       NOT NULL DEFAULT '{}'::jsonb,
    executed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT uq_verification_checks_seq UNIQUE (run_id, seq),
    CONSTRAINT ck_check_code    CHECK (check_code ~ '^[A-Z][A-Z0-9_]+$'),
    CONSTRAINT ck_check_latency CHECK (latency_ms IS NULL OR latency_ms >= 0)
);

-- -----------------------------------------------------------------------------
-- Santé des services & chronologie des phases (vue NOC Avant / Pendant / Après)
-- -----------------------------------------------------------------------------
CREATE TABLE remediation.service_health_samples (
    id          bigint                     GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    service     remediation.service_name   NOT NULL,
    status      remediation.service_status NOT NULL,
    latency_ms  integer,
    http_status smallint,
    observed_at timestamptz                NOT NULL DEFAULT clock_timestamp(),
    details     jsonb                      NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT ck_health_latency CHECK (latency_ms IS NULL OR latency_ms >= 0)
);
CREATE INDEX ix_health_service_observed ON remediation.service_health_samples (service, observed_at DESC);
CREATE INDEX ix_health_observed         ON remediation.service_health_samples (observed_at);

CREATE TABLE remediation.phase_history (
    id          bigint                   GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    phase       remediation.system_phase NOT NULL,
    entered_at  timestamptz              NOT NULL DEFAULT clock_timestamp(),
    incident_id uuid                     REFERENCES remediation.incidents(id),
    reason      varchar(256)             NOT NULL
);
CREATE INDEX ix_phase_history_entered ON remediation.phase_history (entered_at DESC);

-- =============================================================================
-- Déclencheurs
-- =============================================================================
CREATE FUNCTION remediation.fn_forbid_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, remediation AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'RA006', MESSAGE = format('%s.%s is append-only', TG_TABLE_SCHEMA, TG_TABLE_NAME);
END $$;

CREATE FUNCTION remediation.fn_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, remediation AS $$
BEGIN
    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;

CREATE FUNCTION remediation.fn_incidents_before_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, remediation AS $$
BEGIN
    IF NEW.status <> 'OPEN' THEN
        RAISE EXCEPTION USING ERRCODE = 'RA204', MESSAGE = 'an incident must be created in OPEN status';
    END IF;
    NEW.opened_at := clock_timestamp();
    NEW.updated_at := NEW.opened_at;
    NEW.remediation_started_at := NULL;
    NEW.verified_at := NULL;
    NEW.closed_at := NULL;
    NEW.resolution := NULL;
    RETURN NEW;
END $$;

-- Machine à états des incidents + garde du critère de vérification post-reprise.
CREATE FUNCTION remediation.fn_incidents_before_update() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, remediation AS $$
DECLARE
    v_last_status   remediation.verification_status;
    v_last_finished timestamptz;
BEGIN
    IF (NEW.id, NEW.fingerprint, NEW.category, NEW.opened_at) IS DISTINCT FROM (OLD.id, OLD.fingerprint, OLD.category, OLD.opened_at) THEN
        RAISE EXCEPTION USING ERRCODE = 'RA201', MESSAGE = format('immutable incident fields modified on %s', OLD.id);
    END IF;

    -- Champs de cycle de vie posés exclusivement par la base.
    NEW.remediation_started_at := OLD.remediation_started_at;
    NEW.verified_at := OLD.verified_at;
    NEW.closed_at := OLD.closed_at;

    IF NEW.status IS DISTINCT FROM OLD.status THEN
        IF NOT (
               (OLD.status = 'OPEN'        AND NEW.status IN ('TRIAGED', 'SUPPRESSED', 'ESCALATED'))
            OR (OLD.status = 'TRIAGED'     AND NEW.status IN ('REMEDIATING', 'SUPPRESSED', 'ESCALATED'))
            OR (OLD.status = 'REMEDIATING' AND NEW.status IN ('VERIFYING', 'ESCALATED'))
            OR (OLD.status = 'VERIFYING'   AND NEW.status IN ('RESOLVED', 'REMEDIATING', 'ESCALATED'))
            OR (OLD.status = 'ESCALATED'   AND NEW.status IN ('REMEDIATING', 'VERIFYING'))
        ) THEN
            RAISE EXCEPTION USING ERRCODE = 'RA202',
                MESSAGE = format('illegal incident transition %s -> %s on %s', OLD.status, NEW.status, OLD.id);
        END IF;

        IF NEW.status = 'REMEDIATING' THEN
            NEW.remediation_started_at := COALESCE(OLD.remediation_started_at, clock_timestamp());
        ELSIF NEW.status = 'RESOLVED' THEN
            SELECT vr.status, vr.finished_at INTO v_last_status, v_last_finished
              FROM remediation.verification_runs vr
             WHERE vr.incident_id = NEW.id
             ORDER BY vr.started_at DESC, vr.id DESC
             LIMIT 1;
            IF v_last_status IS DISTINCT FROM 'PASSED' THEN
                RAISE EXCEPTION USING ERRCODE = 'RA203',
                    MESSAGE = format('incident %s cannot be RESOLVED: last synthetic verification is %s',
                                     NEW.id, COALESCE(v_last_status::text, 'missing'));
            END IF;
            NEW.verified_at := v_last_finished;
            NEW.closed_at := clock_timestamp();
            NEW.resolution := COALESCE(NEW.resolution, 'AUTOMATIC');
        ELSIF NEW.status = 'SUPPRESSED' THEN
            NEW.closed_at := clock_timestamp();
            NEW.resolution := 'SUPPRESSED';
        END IF;
    ELSIF OLD.status IN ('RESOLVED', 'SUPPRESSED') THEN
        RAISE EXCEPTION USING ERRCODE = 'RA201', MESSAGE = format('closed incident %s is immutable', OLD.id);
    END IF;

    NEW.updated_at := clock_timestamp();
    RETURN NEW;
END $$;

CREATE FUNCTION remediation.fn_incidents_transition_log() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, remediation AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        INSERT INTO remediation.incident_transitions (incident_id, from_status, to_status, reason)
        VALUES (NEW.id, NULL, NEW.status, NEW.status_reason);
    ELSIF NEW.status IS DISTINCT FROM OLD.status THEN
        INSERT INTO remediation.incident_transitions (incident_id, from_status, to_status, reason)
        VALUES (NEW.id, OLD.status, NEW.status, NEW.status_reason);
    END IF;
    RETURN NULL;
END $$;

CREATE TRIGGER trg_incidents_before_insert BEFORE INSERT ON remediation.incidents
    FOR EACH ROW EXECUTE FUNCTION remediation.fn_incidents_before_insert();
CREATE TRIGGER trg_incidents_before_update BEFORE UPDATE ON remediation.incidents
    FOR EACH ROW EXECUTE FUNCTION remediation.fn_incidents_before_update();
CREATE TRIGGER trg_incidents_transition_log AFTER INSERT OR UPDATE OF status ON remediation.incidents
    FOR EACH ROW EXECUTE FUNCTION remediation.fn_incidents_transition_log();
CREATE TRIGGER trg_incidents_no_delete BEFORE DELETE ON remediation.incidents
    FOR EACH ROW EXECUTE FUNCTION remediation.fn_forbid_mutation();

CREATE TRIGGER trg_incident_transitions_immutable BEFORE UPDATE OR DELETE ON remediation.incident_transitions
    FOR EACH ROW EXECUTE FUNCTION remediation.fn_forbid_mutation();
CREATE TRIGGER trg_verification_checks_immutable BEFORE UPDATE OR DELETE ON remediation.verification_checks
    FOR EACH ROW EXECUTE FUNCTION remediation.fn_forbid_mutation();
CREATE TRIGGER trg_phase_history_immutable BEFORE UPDATE OR DELETE ON remediation.phase_history
    FOR EACH ROW EXECUTE FUNCTION remediation.fn_forbid_mutation();
CREATE TRIGGER trg_playbooks_touch BEFORE UPDATE ON remediation.playbooks
    FOR EACH ROW EXECUTE FUNCTION remediation.fn_touch_updated_at();

-- =============================================================================
-- Privilèges : aucun accès aux schémas auth / payment (actions via API uniquement)
-- =============================================================================
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA remediation FROM PUBLIC;

GRANT USAGE ON SCHEMA remediation TO remediation_app;
GRANT SELECT ON ALL TABLES IN SCHEMA remediation TO remediation_app;
GRANT UPDATE (enabled) ON remediation.playbooks TO remediation_app;
GRANT INSERT ON remediation.incidents TO remediation_app;
GRANT UPDATE (severity, status, status_reason, title, playbook_code, attempt_count, alert_count, resolution, last_error)
    ON remediation.incidents TO remediation_app;
GRANT INSERT ON remediation.alerts TO remediation_app;
GRANT UPDATE (incident_id) ON remediation.alerts TO remediation_app;
GRANT INSERT ON remediation.executions TO remediation_app;
GRANT UPDATE (status, finished_at, error) ON remediation.executions TO remediation_app;
GRANT INSERT ON remediation.execution_steps TO remediation_app;
GRANT UPDATE (status, started_at, finished_at, duration_ms, output, error) ON remediation.execution_steps TO remediation_app;
GRANT INSERT ON remediation.verification_runs TO remediation_app;
GRANT UPDATE (status, finished_at, failed_check, synthetic_transaction_ids) ON remediation.verification_runs TO remediation_app;
GRANT INSERT ON remediation.verification_checks TO remediation_app;
GRANT INSERT, DELETE ON remediation.service_health_samples TO remediation_app;
GRANT INSERT ON remediation.phase_history TO remediation_app;

COMMIT;
