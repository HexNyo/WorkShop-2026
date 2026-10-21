-- =============================================================================
-- PROJECT RESILIENCE-ALPHA — 04 : données de référence et jeu de démonstration
-- -----------------------------------------------------------------------------
-- Toutes les données sont FICTIVES. Les principaux sont créés INACTIFS avec un
-- secret non initialisé ('!') : auth-service les active au démarrage à partir
-- des variables d'environnement AUTH_BOOTSTRAP_<USERNAME>_SECRET (cf. .env.example).
-- Les UUID sont fixes afin de relier les comptes de paiement à leurs propriétaires.
-- =============================================================================
SET NAMES utf8mb4;
SET time_zone = '+00:00';
SET sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- -----------------------------------------------------------------------------
-- ra_auth : rôles RBAC
-- -----------------------------------------------------------------------------
INSERT INTO ra_auth.roles (code, description, applies_to, is_privileged) VALUES
    ('payment.customer',     'Initier et consulter ses propres transactions',                       'USER',    false),
    ('payment.operator',     'Consulter l''ensemble des comptes et transactions (lecture seule)',   'USER',    false),
    ('noc.viewer',           'Accès en lecture à la console de supervision et à l''assistant',      'USER',    false),
    ('remediation.admin',    'Piloter le moteur de remédiation (relance, escalade, playbooks)',     'USER',    true),
    ('auth.admin',           'Administrer les principaux et révoquer des jetons',                   'USER',    true),
    ('chaos.operator',       'Injecter des pannes contrôlées (laboratoire, désactivé par défaut)',  'USER',    true),
    ('svc.remediation',      'Actions de remédiation sur payment-api et auth-service',              'SERVICE', true),
    ('svc.synthetic',        'Transactions synthétiques sur les comptes RA-9xxx uniquement',        'SERVICE', false),
    ('svc.detector',         'Émission d''alertes vers le webhook du moteur de remédiation',        'SERVICE', false),
    ('svc.resource_server',  'Synchronisation du flux de révocation des jetons',                    'SERVICE', false);

-- -----------------------------------------------------------------------------
-- ra_auth : principaux (inactifs jusqu'à l'amorçage par auth-service)
-- -----------------------------------------------------------------------------
INSERT INTO ra_auth.principals (id, kind, username, display_name, secret_hash, is_active) VALUES
    ('00000000-0000-4000-8000-000000000001', 'USER',    'admin',            'Administrateur plateforme', '!', false),
    ('00000000-0000-4000-8000-000000000002', 'USER',    'alice',            'Alice Démo',                '!', false),
    ('00000000-0000-4000-8000-000000000003', 'USER',    'bob',              'Bob Démo',                  '!', false),
    ('00000000-0000-4000-8000-000000000004', 'USER',    'merchant',         'Marchand Démo SARL',        '!', false),
    ('00000000-0000-4000-8000-000000000005', 'USER',    'noc-operator',     'Opérateur NOC/SOC',         '!', false),
    ('00000000-0000-4000-8000-000000000101', 'SERVICE', 'svc-remediation',  'remediation-engine',        '!', false),
    ('00000000-0000-4000-8000-000000000102', 'SERVICE', 'svc-synthetic',    'remediation-engine (STM)',  '!', false),
    ('00000000-0000-4000-8000-000000000103', 'SERVICE', 'svc-detector',     'Moteur de détection ML/SIEM','!', false),
    ('00000000-0000-4000-8000-000000000104', 'SERVICE', 'svc-payment-api',  'payment-api',               '!', false);

INSERT INTO ra_auth.principal_roles (principal_id, role_code) VALUES
    ('00000000-0000-4000-8000-000000000001', 'auth.admin'),
    ('00000000-0000-4000-8000-000000000001', 'remediation.admin'),
    ('00000000-0000-4000-8000-000000000001', 'noc.viewer'),
    ('00000000-0000-4000-8000-000000000001', 'payment.operator'),
    ('00000000-0000-4000-8000-000000000001', 'chaos.operator'),
    ('00000000-0000-4000-8000-000000000002', 'payment.customer'),
    ('00000000-0000-4000-8000-000000000003', 'payment.customer'),
    ('00000000-0000-4000-8000-000000000004', 'payment.customer'),
    ('00000000-0000-4000-8000-000000000005', 'noc.viewer'),
    ('00000000-0000-4000-8000-000000000005', 'payment.operator'),
    ('00000000-0000-4000-8000-000000000101', 'svc.remediation'),
    ('00000000-0000-4000-8000-000000000101', 'svc.resource_server'),
    ('00000000-0000-4000-8000-000000000102', 'svc.synthetic'),
    ('00000000-0000-4000-8000-000000000103', 'svc.detector'),
    ('00000000-0000-4000-8000-000000000104', 'svc.resource_server');

-- -----------------------------------------------------------------------------
-- ra_payment : référentiel, comptes fictifs, configuration dynamique
-- -----------------------------------------------------------------------------
INSERT INTO ra_payment.currencies (code, minor_units, label) VALUES
    ('EUR', 2, 'Euro (fictif)'),
    ('USD', 2, 'Dollar US (fictif)');

INSERT INTO ra_payment.accounts (id, account_number, owner_principal_id, holder_name, currency, is_synthetic, opening_balance_minor) VALUES
    ('10000000-0000-4000-8000-000000000001', 'RA-1000-0001', '00000000-0000-4000-8000-000000000002', 'Alice Démo — Courant',   'EUR', false,  500000),
    ('10000000-0000-4000-8000-000000000002', 'RA-1000-0002', '00000000-0000-4000-8000-000000000002', 'Alice Démo — Épargne',   'EUR', false, 1200000),
    ('10000000-0000-4000-8000-000000000003', 'RA-1000-0003', '00000000-0000-4000-8000-000000000003', 'Bob Démo — Courant',     'EUR', false,  250000),
    ('10000000-0000-4000-8000-000000000004', 'RA-1000-0004', '00000000-0000-4000-8000-000000000003', 'Bob Démo — USD',         'USD', false,  100000),
    ('10000000-0000-4000-8000-000000000005', 'RA-2000-0001', '00000000-0000-4000-8000-000000000004', 'Marchand Démo SARL',     'EUR', false,       0),
    ('10000000-0000-4000-8000-000000000006', 'RA-2000-0002', '00000000-0000-4000-8000-000000000004', 'Marchand Démo SARL USD', 'USD', false,       0),
    -- Comptes réservés au Synthetic Transaction Monitoring (aller-retour équilibré).
    ('90000000-0000-4000-8000-000000000001', 'RA-9000-0001', '00000000-0000-4000-8000-000000000102', 'STM Sonde A',            'EUR', true,  1000000),
    ('90000000-0000-4000-8000-000000000002', 'RA-9000-0002', '00000000-0000-4000-8000-000000000102', 'STM Sonde B',            'EUR', true,  1000000);

INSERT INTO ra_payment.runtime_flags (`key`, value, reason) VALUES
    ('write_mode',                            '"READ_WRITE"', 'bootstrap'),
    ('max_transaction_amount_minor',          '1000000',      'bootstrap'),
    ('max_requests_per_minute_per_principal', '600',          'bootstrap');

-- -----------------------------------------------------------------------------
-- ra_remediation : catalogue de playbooks
-- Gabarits : {{incident.target_service}}, {{incident.target_principal_id}},
--            {{incident.target_account_id}}, {{incident.id}}
-- La vérification synthétique est IMPLICITE et OBLIGATOIRE après `steps` ;
-- `post_verification_steps` ne s'exécutent qu'après une vérification PASSED.
-- -----------------------------------------------------------------------------
INSERT INTO ra_remediation.playbooks (code, category, title, description, steps, post_verification_steps, max_attempts, step_timeout_seconds, cooldown_seconds) VALUES
(
    'PB-SERVICE-RESTART', 'SERVICE_UNAVAILABLE',
    'Redémarrage contrôlé du service',
    'Redémarre le conteneur ciblé via le proxy Docker restreint puis attend la readiness.',
    '[
        {"action": "docker.restart_container", "target": "{{incident.target_service}}", "params": {"stop_timeout_seconds": 10}},
        {"action": "probe.wait_ready",         "target": "{{incident.target_service}}", "params": {"timeout_seconds": 60, "interval_seconds": 2}}
     ]',
    '[]', 3, 90, 30
),
(
    'PB-PERF-RECOVERY', 'PERFORMANCE_DEGRADATION',
    'Rétablissement des performances',
    'Bride le débit par principal, recycle le service puis lève le bridage après vérification.',
    '[
        {"action": "payment.set_runtime_flag", "target": "payment-api", "params": {"key": "max_requests_per_minute_per_principal", "value": 60}},
        {"action": "docker.restart_container", "target": "{{incident.target_service}}", "params": {"stop_timeout_seconds": 10}},
        {"action": "probe.wait_ready",         "target": "{{incident.target_service}}", "params": {"timeout_seconds": 60, "interval_seconds": 2}}
     ]',
    '[
        {"action": "payment.set_runtime_flag", "target": "payment-api", "params": {"key": "max_requests_per_minute_per_principal", "value": 600}}
     ]', 2, 90, 60
),
(
    'PB-RESOURCE-RECOVERY', 'RESOURCE_EXHAUSTION',
    'Libération des ressources épuisées',
    'Passe en quarantaine synthétique, purge les transactions bloquées, recycle le service.',
    '[
        {"action": "payment.set_write_mode",   "target": "payment-api", "params": {"mode": "SYNTHETIC_ONLY"}},
        {"action": "payment.purge_stale",      "target": "payment-api", "params": {"older_than_seconds": 120}},
        {"action": "docker.restart_container", "target": "{{incident.target_service}}", "params": {"stop_timeout_seconds": 10}},
        {"action": "probe.wait_ready",         "target": "{{incident.target_service}}", "params": {"timeout_seconds": 60, "interval_seconds": 2}}
     ]',
    '[
        {"action": "payment.set_write_mode",   "target": "payment-api", "params": {"mode": "READ_WRITE"}}
     ]', 2, 90, 60
),
(
    'PB-INTEGRITY-RESTORE', 'DATA_INTEGRITY_VIOLATION',
    'Restauration de la cohérence des données',
    'Quarantaine, diagnostic, purge des états en vol, reconstruction des soldes depuis le grand livre, contrôle final.',
    '[
        {"action": "payment.set_write_mode",     "target": "payment-api", "params": {"mode": "SYNTHETIC_ONLY"}},
        {"action": "payment.integrity_report",   "target": "payment-api", "params": {"require_pass": false}},
        {"action": "payment.purge_stale",        "target": "payment-api", "params": {"older_than_seconds": 120}},
        {"action": "payment.repair_balances",    "target": "payment-api", "params": {"dry_run": false}},
        {"action": "payment.integrity_report",   "target": "payment-api", "params": {"require_pass": true}}
     ]',
    '[
        {"action": "payment.set_write_mode",     "target": "payment-api", "params": {"mode": "READ_WRITE"}}
     ]', 2, 120, 60
),
(
    'PB-CREDENTIAL-CONTAINMENT', 'CREDENTIAL_COMPROMISE',
    'Confinement d''identifiants compromis',
    'Révoque tous les jetons du principal suspect et le désactive (réactivation humaine uniquement).',
    '[
        {"action": "auth.revoke_principal_tokens", "target": "{{incident.target_principal_id}}", "params": {"reason": "CREDENTIAL_COMPROMISE"}},
        {"action": "auth.disable_principal",       "target": "{{incident.target_principal_id}}", "params": {"reason": "CREDENTIAL_COMPROMISE"}}
     ]',
    '[]', 2, 30, 0
),
(
    'PB-TRAFFIC-ISOLATION', 'ANOMALOUS_TRAFFIC',
    'Isolation d''un trafic anormal',
    'Quarantaine synthétique, bridage, révocation des jetons du principal source si identifié.',
    '[
        {"action": "payment.set_write_mode",       "target": "payment-api", "params": {"mode": "SYNTHETIC_ONLY"}},
        {"action": "payment.set_runtime_flag",     "target": "payment-api", "params": {"key": "max_requests_per_minute_per_principal", "value": 30}},
        {"action": "auth.revoke_principal_tokens", "target": "{{incident.target_principal_id}}", "params": {"reason": "ANOMALOUS_TRAFFIC"}, "optional": true}
     ]',
    '[
        {"action": "payment.set_runtime_flag",     "target": "payment-api", "params": {"key": "max_requests_per_minute_per_principal", "value": 600}},
        {"action": "payment.set_write_mode",       "target": "payment-api", "params": {"mode": "READ_WRITE"}}
     ]', 2, 30, 60
),
(
    'PB-FRAUD-CONTAINMENT', 'FRAUD_PATTERN',
    'Confinement d''un schéma de fraude',
    'Gèle le compte ciblé et révoque les jetons du principal initiateur.',
    '[
        {"action": "payment.freeze_account",       "target": "{{incident.target_account_id}}",   "params": {"reason": "FRAUD_PATTERN"}},
        {"action": "auth.revoke_principal_tokens", "target": "{{incident.target_principal_id}}", "params": {"reason": "FRAUD_PATTERN"}, "optional": true}
     ]',
    '[]', 2, 30, 0
);

INSERT INTO ra_remediation.phase_history (phase, reason) VALUES ('NOMINAL', 'platform bootstrap');

