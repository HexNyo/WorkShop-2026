-- =============================================================================
-- PROJECT RESILIENCE-ALPHA — 06 : empreintes faciales (auth-service, étape 1 du login)
-- -----------------------------------------------------------------------------
-- Seul le vecteur SFace (128 float32 = 512 octets) est conservé, jamais l'image.
-- Idempotent : sur une base existante, appliquer à la main avec
--   docker compose exec -T postgres psql -U postgres -d resilience < database/init/06_auth_face.sql
-- =============================================================================
\set ON_ERROR_STOP on
BEGIN;
SET LOCAL ROLE ra_owner;

CREATE TABLE IF NOT EXISTS auth.face_embeddings (
    principal_id uuid        PRIMARY KEY REFERENCES auth.principals(id) ON DELETE CASCADE,
    embedding    bytea       NOT NULL,
    enrolled_at  timestamptz NOT NULL DEFAULT now(),
    enrolled_by  uuid        REFERENCES auth.principals(id) ON DELETE SET NULL,
    CONSTRAINT ck_face_embedding_size CHECK (octet_length(embedding) = 512)
);
COMMENT ON TABLE auth.face_embeddings IS 'Empreinte biométrique SFace par utilisateur (aucune image stockée)';

GRANT SELECT, INSERT, UPDATE ON auth.face_embeddings TO auth_app;

COMMIT;
