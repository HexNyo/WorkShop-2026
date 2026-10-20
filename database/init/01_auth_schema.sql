-- =============================================================================
-- PROJECT RESILIENCE-ALPHA — 01 : schéma `auth` (propriété fonctionnelle : auth-service)
-- -----------------------------------------------------------------------------
-- Principaux (utilisateurs humains et comptes de service M2M), rôles RBAC,
-- jetons de rafraîchissement (stockés hachés), flux de révocation et audit.
-- Aucun secret n'est stocké en clair : secret_hash = Argon2id, token_hash = SHA-256.
-- =============================================================================
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL ROLE ra_owner;

CREATE SCHEMA auth;
REVOKE ALL ON SCHEMA auth FROM PUBLIC;
COMMENT ON SCHEMA auth IS 'Identités, RBAC et cycle de vie des jetons (auth-service)';

CREATE TYPE auth.principal_kind AS ENUM ('USER', 'SERVICE');
CREATE TYPE auth.revocation_kind AS ENUM ('JTI', 'PRINCIPAL');

-- -----------------------------------------------------------------------------
-- Rôles RBAC
-- -----------------------------------------------------------------------------
CREATE TABLE auth.roles (
    code          varchar(64)         PRIMARY KEY,
    description   text                NOT NULL,
    applies_to    auth.principal_kind NOT NULL,
    is_privileged boolean             NOT NULL DEFAULT false,
    CONSTRAINT ck_roles_code_format CHECK (code ~ '^[a-z]+(\.[a-z_]+)+$')
);
COMMENT ON COLUMN auth.roles.applies_to IS 'Un rôle de service (svc.*) ne peut jamais être porté par un humain, et réciproquement';

-- -----------------------------------------------------------------------------
-- Principaux
-- -----------------------------------------------------------------------------
CREATE TABLE auth.principals (
    id                 uuid                PRIMARY KEY DEFAULT gen_random_uuid(),
    kind               auth.principal_kind NOT NULL,
    username           varchar(64)         NOT NULL,
    display_name       varchar(128)        NOT NULL,
    secret_hash        text                NOT NULL,
    is_active          boolean             NOT NULL DEFAULT true,
    failed_login_count integer             NOT NULL DEFAULT 0,
    locked_until       timestamptz,
    tokens_valid_after timestamptz         NOT NULL DEFAULT '-infinity',
    last_login_at      timestamptz,
    created_at         timestamptz         NOT NULL DEFAULT now(),
    updated_at         timestamptz         NOT NULL DEFAULT now(),
    CONSTRAINT uq_principals_username UNIQUE (username),
    CONSTRAINT ck_principals_username CHECK (username ~ '^[a-z0-9][a-z0-9._-]{2,63}$'),
    CONSTRAINT ck_principals_failed CHECK (failed_login_count >= 0),
    -- '!' = secret non initialisé (connexion impossible), sinon empreinte Argon2id PHC.
    CONSTRAINT ck_principals_secret CHECK (secret_hash = '!' OR secret_hash LIKE '$argon2id$%'),
    CONSTRAINT ck_principals_inactive_without_secret CHECK (secret_hash <> '!' OR NOT is_active)
);
COMMENT ON COLUMN auth.principals.tokens_valid_after IS 'Tout jeton dont iat < cette date est invalide (révocation globale du principal)';

CREATE TABLE auth.principal_roles (
    principal_id uuid        NOT NULL REFERENCES auth.principals(id) ON DELETE CASCADE,
    role_code    varchar(64) NOT NULL REFERENCES auth.roles(code) ON DELETE RESTRICT,
    granted_at   timestamptz NOT NULL DEFAULT now(),
    granted_by   uuid        REFERENCES auth.principals(id) ON DELETE SET NULL,
    PRIMARY KEY (principal_id, role_code)
);
CREATE INDEX ix_principal_roles_role ON auth.principal_roles (role_code);

-- -----------------------------------------------------------------------------
-- Jetons de rafraîchissement (rotation + détection de réutilisation par famille)
-- -----------------------------------------------------------------------------
CREATE TABLE auth.refresh_tokens (
    id            uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
    family_id     uuid         NOT NULL,
    principal_id  uuid         NOT NULL REFERENCES auth.principals(id) ON DELETE CASCADE,
    token_hash    bytea        NOT NULL,
    issued_at     timestamptz  NOT NULL DEFAULT now(),
    expires_at    timestamptz  NOT NULL,
    used_at       timestamptz,
    revoked_at    timestamptz,
    revoke_reason varchar(64),
    client_ip     inet,
    user_agent    varchar(256),
    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash),
    CONSTRAINT ck_refresh_hash_len CHECK (octet_length(token_hash) = 32),
    CONSTRAINT ck_refresh_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_refresh_revocation CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
);
CREATE INDEX ix_refresh_family ON auth.refresh_tokens (family_id);
CREATE INDEX ix_refresh_principal_active ON auth.refresh_tokens (principal_id) WHERE revoked_at IS NULL;
CREATE INDEX ix_refresh_expires ON auth.refresh_tokens (expires_at);

-- -----------------------------------------------------------------------------
-- Flux de révocation des jetons d'accès (consommé par les resource servers)
-- -----------------------------------------------------------------------------
CREATE TABLE auth.revocation_events (
    seq          bigint               GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind         auth.revocation_kind NOT NULL,
    jti          uuid,
    principal_id uuid                 REFERENCES auth.principals(id) ON DELETE CASCADE,
    not_before   timestamptz,
    expires_at   timestamptz          NOT NULL,
    reason       varchar(64)          NOT NULL,
    created_at   timestamptz          NOT NULL DEFAULT now(),
    CONSTRAINT ck_revocation_shape CHECK (
        (kind = 'JTI'       AND jti IS NOT NULL AND not_before IS NULL) OR
        (kind = 'PRINCIPAL' AND jti IS NULL AND principal_id IS NOT NULL AND not_before IS NOT NULL)
    ),
    CONSTRAINT ck_revocation_reason CHECK (reason ~ '^[A-Z][A-Z_]+$')
);
CREATE UNIQUE INDEX uq_revocation_jti ON auth.revocation_events (jti) WHERE kind = 'JTI';
CREATE INDEX ix_revocation_expires ON auth.revocation_events (expires_at);
COMMENT ON COLUMN auth.revocation_events.expires_at IS 'Horizon de purge : au-delà, tout jeton concerné est de toute façon expiré';

-- -----------------------------------------------------------------------------
-- Journal d'audit (append-only)
-- -----------------------------------------------------------------------------
CREATE TABLE auth.audit_events (
    id                 bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    occurred_at        timestamptz NOT NULL DEFAULT now(),
    event_type         varchar(64) NOT NULL,
    outcome            varchar(16) NOT NULL,
    principal_id       uuid,
    actor_principal_id uuid,
    client_ip          inet,
    correlation_id     varchar(64),
    details            jsonb       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT ck_audit_event_type CHECK (event_type ~ '^[A-Z][A-Z_]+$'),
    CONSTRAINT ck_audit_outcome CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED'))
);
CREATE INDEX ix_audit_occurred ON auth.audit_events (occurred_at DESC);
CREATE INDEX ix_audit_principal ON auth.audit_events (principal_id, occurred_at DESC);

-- -----------------------------------------------------------------------------
-- Fonctions & déclencheurs
-- -----------------------------------------------------------------------------
CREATE FUNCTION auth.fn_touch_updated_at() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, auth AS $$
BEGIN
    NEW.updated_at := now();
    RETURN NEW;
END $$;

CREATE TRIGGER trg_principals_touch BEFORE UPDATE ON auth.principals
    FOR EACH ROW EXECUTE FUNCTION auth.fn_touch_updated_at();

-- Cohérence type de principal / type de rôle.
CREATE FUNCTION auth.fn_principal_roles_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, auth AS $$
DECLARE
    v_principal_kind auth.principal_kind;
    v_role_kind      auth.principal_kind;
BEGIN
    SELECT kind INTO v_principal_kind FROM auth.principals WHERE id = NEW.principal_id;
    SELECT applies_to INTO v_role_kind FROM auth.roles WHERE code = NEW.role_code;
    IF v_principal_kind IS NOT NULL AND v_role_kind IS NOT NULL AND v_principal_kind <> v_role_kind THEN
        RAISE EXCEPTION USING
            ERRCODE = 'RA101',
            MESSAGE = format('role %s (%s) cannot be granted to a %s principal', NEW.role_code, v_role_kind, v_principal_kind);
    END IF;
    RETURN NEW;
END $$;

CREATE TRIGGER trg_principal_roles_guard BEFORE INSERT OR UPDATE ON auth.principal_roles
    FOR EACH ROW EXECUTE FUNCTION auth.fn_principal_roles_guard();

-- Le journal d'audit est immuable.
CREATE FUNCTION auth.fn_forbid_mutation() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, auth AS $$
BEGIN
    RAISE EXCEPTION USING ERRCODE = 'RA006', MESSAGE = format('%s.%s is append-only', TG_TABLE_SCHEMA, TG_TABLE_NAME);
END $$;

CREATE TRIGGER trg_audit_immutable BEFORE UPDATE OR DELETE ON auth.audit_events
    FOR EACH ROW EXECUTE FUNCTION auth.fn_forbid_mutation();
CREATE TRIGGER trg_audit_no_truncate BEFORE TRUNCATE ON auth.audit_events
    FOR EACH STATEMENT EXECUTE FUNCTION auth.fn_forbid_mutation();

-- -----------------------------------------------------------------------------
-- Privilèges (moindre privilège : auth_app ne voit que le schéma auth)
-- -----------------------------------------------------------------------------
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA auth FROM PUBLIC;

GRANT USAGE ON SCHEMA auth TO auth_app;
GRANT SELECT ON auth.roles TO auth_app;
GRANT SELECT, INSERT ON auth.principals TO auth_app;
GRANT UPDATE (display_name, secret_hash, is_active, failed_login_count, locked_until, tokens_valid_after, last_login_at)
    ON auth.principals TO auth_app;
GRANT SELECT, INSERT, DELETE ON auth.principal_roles TO auth_app;
GRANT SELECT, INSERT, DELETE ON auth.refresh_tokens TO auth_app;
GRANT UPDATE (used_at, revoked_at, revoke_reason) ON auth.refresh_tokens TO auth_app;
GRANT SELECT, INSERT, DELETE ON auth.revocation_events TO auth_app;
GRANT SELECT, INSERT ON auth.audit_events TO auth_app;

COMMIT;
