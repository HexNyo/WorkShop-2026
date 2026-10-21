-- =============================================================================
-- PROJECT RESILIENCE-ALPHA — 01 : base `ra_auth` (propriété fonctionnelle : auth-service)
-- -----------------------------------------------------------------------------
-- Principaux (utilisateurs humains et comptes de service M2M), rôles RBAC,
-- jetons de rafraîchissement (stockés hachés), flux de révocation, audit et
-- empreintes faciales. Aucun secret en clair : secret_hash = Argon2id,
-- token_hash = SHA-256, empreinte faciale = vecteur SFace (jamais l'image).
-- Horodatages DATETIME(6) en UTC (les sessions applicatives imposent time_zone=+00:00).
-- =============================================================================
SET NAMES utf8mb4;
SET time_zone = '+00:00';
SET sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- utf8mb4_bin : comparaisons, unicité et REGEXP sensibles à la casse (comme PostgreSQL).
CREATE DATABASE ra_auth CHARACTER SET utf8mb4 COLLATE utf8mb4_bin
    COMMENT 'Identités, RBAC et cycle de vie des jetons (auth-service)';

-- -----------------------------------------------------------------------------
-- Rôles RBAC
-- -----------------------------------------------------------------------------
CREATE TABLE ra_auth.roles (
    code          VARCHAR(64)             NOT NULL PRIMARY KEY,
    description   TEXT                    NOT NULL,
    applies_to    ENUM('USER', 'SERVICE') NOT NULL
                  COMMENT 'Un rôle de service (svc.*) ne peut jamais être porté par un humain, et réciproquement',
    is_privileged BOOLEAN                 NOT NULL DEFAULT FALSE,
    CONSTRAINT ck_roles_code_format CHECK (code REGEXP '^[a-z]+(\\.[a-z_]+)+$')
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Principaux
-- -----------------------------------------------------------------------------
CREATE TABLE ra_auth.principals (
    id                 CHAR(36) CHARACTER SET ascii NOT NULL DEFAULT (UUID()) PRIMARY KEY,
    kind               ENUM('USER', 'SERVICE') NOT NULL,
    username           VARCHAR(64)             NOT NULL,
    display_name       VARCHAR(128)            NOT NULL,
    secret_hash        VARCHAR(255)            NOT NULL,
    is_active          BOOLEAN                 NOT NULL DEFAULT TRUE,
    failed_login_count INT                     NOT NULL DEFAULT 0,
    locked_until       DATETIME(6),
    tokens_valid_after DATETIME(6)             NOT NULL DEFAULT '1000-01-01 00:00:00'
                       COMMENT 'Tout jeton dont iat < cette date est invalide (révocation globale du principal)',
    last_login_at      DATETIME(6),
    created_at         DATETIME(6)             NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    updated_at         DATETIME(6)             NOT NULL DEFAULT CURRENT_TIMESTAMP(6) ON UPDATE CURRENT_TIMESTAMP(6),
    CONSTRAINT uq_principals_username UNIQUE (username),
    CONSTRAINT ck_principals_username CHECK (username REGEXP '^[a-z0-9][a-z0-9._-]{2,63}$'),
    CONSTRAINT ck_principals_failed CHECK (failed_login_count >= 0),
    -- '!' = secret non initialisé (connexion impossible), sinon empreinte Argon2id PHC.
    CONSTRAINT ck_principals_secret CHECK (secret_hash = '!' OR secret_hash LIKE '$argon2id$%'),
    CONSTRAINT ck_principals_inactive_without_secret CHECK (secret_hash <> '!' OR NOT is_active)
) ENGINE = InnoDB;

CREATE TABLE ra_auth.principal_roles (
    principal_id CHAR(36) CHARACTER SET ascii NOT NULL,
    role_code    VARCHAR(64) NOT NULL,
    granted_at   DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    granted_by   CHAR(36) CHARACTER SET ascii,
    PRIMARY KEY (principal_id, role_code),
    INDEX ix_principal_roles_role (role_code),
    CONSTRAINT fk_principal_roles_principal FOREIGN KEY (principal_id) REFERENCES ra_auth.principals (id) ON DELETE CASCADE,
    CONSTRAINT fk_principal_roles_role FOREIGN KEY (role_code) REFERENCES ra_auth.roles (code) ON DELETE RESTRICT,
    CONSTRAINT fk_principal_roles_granted_by FOREIGN KEY (granted_by) REFERENCES ra_auth.principals (id) ON DELETE SET NULL
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Jetons de rafraîchissement (rotation + détection de réutilisation par famille)
-- -----------------------------------------------------------------------------
CREATE TABLE ra_auth.refresh_tokens (
    id            CHAR(36) CHARACTER SET ascii NOT NULL PRIMARY KEY,
    family_id     CHAR(36) CHARACTER SET ascii NOT NULL,
    principal_id  CHAR(36) CHARACTER SET ascii NOT NULL,
    token_hash    VARBINARY(32) NOT NULL,
    issued_at     DATETIME(6)   NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    expires_at    DATETIME(6)   NOT NULL,
    used_at       DATETIME(6),
    revoked_at    DATETIME(6),
    revoke_reason VARCHAR(64),
    client_ip     VARCHAR(45),
    user_agent    VARCHAR(256),
    CONSTRAINT uq_refresh_token_hash UNIQUE (token_hash),
    INDEX ix_refresh_family (family_id),
    INDEX ix_refresh_principal_active (principal_id, revoked_at),
    INDEX ix_refresh_expires (expires_at),
    CONSTRAINT fk_refresh_principal FOREIGN KEY (principal_id) REFERENCES ra_auth.principals (id) ON DELETE CASCADE,
    CONSTRAINT ck_refresh_hash_len CHECK (LENGTH(token_hash) = 32),
    CONSTRAINT ck_refresh_expiry CHECK (expires_at > issued_at),
    CONSTRAINT ck_refresh_revocation CHECK ((revoked_at IS NULL) = (revoke_reason IS NULL))
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Flux de révocation des jetons d'accès (consommé par les resource servers)
-- -----------------------------------------------------------------------------
CREATE TABLE ra_auth.revocation_events (
    seq          BIGINT                  NOT NULL AUTO_INCREMENT PRIMARY KEY,
    kind         ENUM('JTI', 'PRINCIPAL') NOT NULL,
    jti          CHAR(36) CHARACTER SET ascii,
    principal_id CHAR(36) CHARACTER SET ascii,
    not_before   DATETIME(6),
    expires_at   DATETIME(6)             NOT NULL
                 COMMENT 'Horizon de purge : au-delà, tout jeton concerné est de toute façon expiré',
    reason       VARCHAR(64)             NOT NULL,
    created_at   DATETIME(6)             NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    -- jti n'est renseigné que pour kind = 'JTI' (ck_revocation_shape) : unicité simple.
    CONSTRAINT uq_revocation_jti UNIQUE (jti),
    INDEX ix_revocation_expires (expires_at),
    CONSTRAINT fk_revocation_principal FOREIGN KEY (principal_id) REFERENCES ra_auth.principals (id) ON DELETE CASCADE,
    CONSTRAINT ck_revocation_shape CHECK (
        (kind = 'JTI'       AND jti IS NOT NULL AND not_before IS NULL) OR
        (kind = 'PRINCIPAL' AND jti IS NULL AND principal_id IS NOT NULL AND not_before IS NOT NULL)
    ),
    CONSTRAINT ck_revocation_reason CHECK (reason REGEXP '^[A-Z][A-Z_]+$')
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Journal d'audit (append-only)
-- -----------------------------------------------------------------------------
CREATE TABLE ra_auth.audit_events (
    id                 BIGINT      NOT NULL AUTO_INCREMENT PRIMARY KEY,
    occurred_at        DATETIME(6) NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    event_type         VARCHAR(64) NOT NULL,
    outcome            VARCHAR(16) NOT NULL,
    principal_id       CHAR(36) CHARACTER SET ascii,
    actor_principal_id CHAR(36) CHARACTER SET ascii,
    client_ip          VARCHAR(45),
    correlation_id     VARCHAR(64),
    details            JSON        NOT NULL DEFAULT '{}',
    INDEX ix_audit_occurred (occurred_at),
    INDEX ix_audit_principal (principal_id, occurred_at),
    CONSTRAINT ck_audit_event_type CHECK (event_type REGEXP '^[A-Z][A-Z_]+$'),
    CONSTRAINT ck_audit_outcome CHECK (outcome IN ('SUCCESS', 'FAILURE', 'DENIED'))
) ENGINE = InnoDB;

-- -----------------------------------------------------------------------------
-- Empreintes faciales (étape 1 du login) : vecteur SFace, 128 float32 = 512 octets
-- -----------------------------------------------------------------------------
CREATE TABLE ra_auth.face_embeddings (
    principal_id CHAR(36) CHARACTER SET ascii NOT NULL PRIMARY KEY,
    embedding    VARBINARY(512) NOT NULL,
    enrolled_at  DATETIME(6)    NOT NULL DEFAULT CURRENT_TIMESTAMP(6),
    enrolled_by  CHAR(36) CHARACTER SET ascii,
    CONSTRAINT fk_face_principal FOREIGN KEY (principal_id) REFERENCES ra_auth.principals (id) ON DELETE CASCADE,
    CONSTRAINT fk_face_enrolled_by FOREIGN KEY (enrolled_by) REFERENCES ra_auth.principals (id) ON DELETE SET NULL,
    CONSTRAINT ck_face_embedding_size CHECK (LENGTH(embedding) = 512)
) ENGINE = InnoDB COMMENT 'Empreinte biométrique SFace par utilisateur (aucune image stockée)';

-- -----------------------------------------------------------------------------
-- Déclencheurs (exécutés avec les droits de ra_owner)
-- -----------------------------------------------------------------------------
DELIMITER $$

-- Cohérence type de principal / type de rôle.
CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_auth.trg_principal_roles_guard
BEFORE INSERT ON ra_auth.principal_roles FOR EACH ROW
BEGIN
    DECLARE v_principal_kind VARCHAR(16) DEFAULT (SELECT kind FROM ra_auth.principals WHERE id = NEW.principal_id);
    DECLARE v_role_kind      VARCHAR(16) DEFAULT (SELECT applies_to FROM ra_auth.roles WHERE code = NEW.role_code);
    DECLARE v_msg            VARCHAR(128);
    IF v_principal_kind IS NOT NULL AND v_role_kind IS NOT NULL AND v_principal_kind <> v_role_kind THEN
        SET v_msg = CONCAT('RA101 role ', NEW.role_code, ' (', v_role_kind, ') cannot be granted to a ', v_principal_kind, ' principal');
        SIGNAL SQLSTATE 'RA101' SET MESSAGE_TEXT = v_msg;
    END IF;
END $$

-- Le journal d'audit est immuable (TRUNCATE exige DROP, jamais accordé aux comptes applicatifs).
CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_auth.trg_audit_no_update
BEFORE UPDATE ON ra_auth.audit_events FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_auth.audit_events is append-only' $$

CREATE DEFINER = 'ra_owner'@'localhost' TRIGGER ra_auth.trg_audit_no_delete
BEFORE DELETE ON ra_auth.audit_events FOR EACH ROW
    SIGNAL SQLSTATE 'RA006' SET MESSAGE_TEXT = 'RA006 ra_auth.audit_events is append-only' $$

DELIMITER ;

-- -----------------------------------------------------------------------------
-- Privilèges (moindre privilège : ra_auth_app ne voit que la base ra_auth)
-- -----------------------------------------------------------------------------
GRANT SELECT ON ra_auth.roles TO ra_auth_app_role;
GRANT SELECT, INSERT,
      UPDATE (display_name, secret_hash, is_active, failed_login_count, locked_until, tokens_valid_after, last_login_at)
    ON ra_auth.principals TO ra_auth_app_role;
GRANT SELECT, INSERT, DELETE ON ra_auth.principal_roles TO ra_auth_app_role;
GRANT SELECT, INSERT, DELETE, UPDATE (used_at, revoked_at, revoke_reason) ON ra_auth.refresh_tokens TO ra_auth_app_role;
GRANT SELECT, INSERT, DELETE ON ra_auth.revocation_events TO ra_auth_app_role;
GRANT SELECT, INSERT ON ra_auth.audit_events TO ra_auth_app_role;
-- UPDATE complet : INSERT … ON DUPLICATE KEY UPDATE l'exige aussi sur la clé (principal_id).
GRANT SELECT, INSERT, UPDATE, DELETE ON ra_auth.face_embeddings TO ra_auth_app_role;
