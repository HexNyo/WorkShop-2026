# 01 — Architecture applicative

> PROJECT RESILIENCE-ALPHA · Lot « Développement applicatif et orchestration de la remédiation »
> Statut : **Lot 1 — à valider**

## 1. Vue d'ensemble

La plateforme simule un système de paiement critique (données 100 % fictives) et démontre une boucle de **reprise autonome sans intervention humaine** : détection → décision → remédiation → **vérification synthétique de bout en bout** → clôture.

```mermaid
flowchart LR
    subgraph EDGE["réseau edge (seul exposé)"]
        GW["frontend-dashboard<br/>nginx non-root :8080<br/>SPA React + passerelle"]
    end

    subgraph APP["réseau app (internal)"]
        AUTH["auth-service<br/>FastAPI :8000"]
        PAY["payment-api<br/>FastAPI :8000"]
        SUP["remediation-engine<br/>listener SUPERVISION :8002<br/>(lecture seule)"]
        RAG["agent documentaire RAG<br/>(autre lot)"]
    end

    subgraph CTRL["réseau control (internal)"]
        RE["remediation-engine<br/>listener CONTROL :8001<br/>webhook + orchestration"]
        DET["moteur de détection ML/SIEM<br/>(autre lot)"]
    end

    subgraph DOCK["réseau docker-ctl (internal)"]
        SP["socket-proxy<br/>allowlist : restart uniquement"]
    end

    subgraph DATA["réseau data (internal)"]
        PG[("MariaDB externe<br/>bases ra_auth / ra_payment / ra_remediation")]
    end

    Browser((Navigateur)) -->|HTTPS| GW
    GW -->|/api/auth/v1/*| AUTH
    GW -->|/api/payment/v1/*| PAY
    GW -->|/api/supervision/v1/*| SUP
    GW -->|/api/assistant/v1/* + auth_request| RAG

    DET -->|POST /v1/alerts<br/>JWT + HMAC| RE
    RE -->|/admin/v1/* · svc.remediation| PAY
    RE -->|/internal/v1/* · svc.remediation| AUTH
    RE -->|STM · svc.synthetic| PAY
    RE -->|POST /containers/{name}/restart| SP

    AUTH --- PG
    PAY --- PG
    RE --- PG
```

`remediation-engine` est **un seul processus** exposant **deux listeners HTTP distincts**, chacun lié à l'adresse IP d'un seul réseau Docker :

| Listener | Bind | Réseau | Rôle | Joignable depuis |
|---|---|---|---|---|
| CONTROL | `CONTROL_BIND_HOST:8001` | `control` | Webhook d'alertes, pilotage des incidents/playbooks | moteur de détection, opérateur via `docker exec` |
| SUPERVISION | `SUPERVISION_BIND_HOST:8002` | `app` | Lecture seule + flux SSE pour la console | passerelle uniquement |

L'interface d'orchestration n'est donc **jamais routable** depuis la passerelle publique (défense réseau), et reste de toute façon protégée par JWT + HMAC (défense applicative).

## 2. Composants

| Composant | Techno | Responsabilité | Rôle(s) BDD |
|---|---|---|---|
| `auth-service` | Python 3.12 · FastAPI · PyJWT (RS256) · argon2-cffi | Login humain, `client_credentials` M2M, refresh rotatif, révocation, JWKS, RBAC | `auth_app` |
| `payment-api` | Python 3.12 · FastAPI · aiomysql (SQL explicite, invariants en base) · outbox → SSE | Cycle de vie des transactions, idempotence, santé avancée, administration de remédiation | `ra_payment_app` (runtime), `ra_payment_maint` (admin) |
| `database` | MariaDB >= 10.6 (instance externe) | Persistance, invariants financiers en base (triggers, contraintes, procédures), intégrité/réparation | — |
| `remediation-engine` | Python 3.12 · FastAPI · asyncio · httpx · 2 serveurs uvicorn dans un processus | Webhook, machine à états d'incident, runner de playbooks, connecteurs, STM, watchdog intégré, flux SSE, CLI `ra-ctl` | `remediation_app` |
| `frontend-dashboard` | React 18 · TypeScript · Vite · Tailwind CSS · nginx-unprivileged | SPA (Portail métier, NOC/SOC, Assistant) + passerelle reverse-proxy | — |
| `socket-proxy` | wollomatic/socket-proxy 1.10.0 (uid 65534, groupe du socket) | Accès Docker restreint : `GET /_ping`, `GET /containers/json`, `POST /containers/<id 64 hex>/restart` ; client autorisé : 172.30.40.10 uniquement | — |

## 3. Arborescence cible du monorepo

Légende : ✅ livré au Lot 1 · 🔜 lot indiqué.

```text
resilience-alpha/
├── README.md                                   ✅
├── .env.example                                ✅  modèle de configuration (aucune valeur secrète)
├── .gitignore                                  ✅
├── .editorconfig                               ✅
├── docker-compose.yml                          ✅  L2 (enrichi à chaque lot) — profil `test` pour les e2e
├── Makefile                                    ✅  L2  (secrets, up, down, reset, test…)
├── docs/
│   ├── 01-architecture.md                      ✅
│   ├── 02-modele-donnees.md                    ✅
│   ├── 03-contrats-api.md                      ✅
│   └── 04-boucle-remediation.md                ✅
├── contracts/
│   ├── alert-webhook.schema.json               ✅  contrat avec le lot Détection
│   └── sse-events.schema.json                  ✅  contrat avec le Frontend
├── scripts/
│   ├── generate-dev-secrets.sh                 ✅  L2  génère clé RSA 3072 + secrets aléatoires dans .env
│   └── test-database.sh                        ✅  L2  suite d'acceptation sur base éphémère
├── database/
│   ├── Dockerfile                              ✅  L2  cibles runtime (non-root) / test
│   ├── init/
│   │   ├── 00_roles.sh                         ✅  rôles + durcissement (secrets via \getenv)
│   │   ├── 01_auth_schema.sql                  ✅
│   │   ├── 02_payment_schema.sql               ✅
│   │   ├── 03_remediation_schema.sql           ✅
│   │   ├── 04_seed.sql                         ✅
│   │   ├── 05_hba.sh                           ✅  L2  superutilisateur local uniquement, SCRAM pour les rôles applicatifs
│   │   └── 90_chaos_lab.sh                     ✅  installé seulement si CHAOS_LAB_ENABLED=true
│   └── tests/
│       └── test_invariants.sh                  ✅  43 assertions (pg_hba, invariants, privilèges, attaque/réparation)
├── libs/
│   └── python/ra_common/                       ✅  L2  bibliothèque partagée
│       ├── pyproject.toml
│       └── ra_common/
│           ├── context.py                      contexte de requête (request/trace/corrélation/principal)
│           ├── logging.py                      logs JSON structurés, masquage des secrets
│           ├── middleware.py                   X-Request-ID, traceparent, journal d'accès, métriques
│           ├── problem.py                      RFC 9457 problem+json + handlers
│           ├── health.py                       format application/health+json
│           ├── metrics.py                      métriques Prometheus communes
│           ├── db.py                           L3  pool aiomysql, transactions, SQLSTATE applicatifs
│           ├── sse.py                          L3  tickets signés, diffusion avec reprise, flux SSE
│           ├── ratelimit.py                    L4  fenêtre glissante par clé (quotas, webhook)
│           └── security/
│               ├── verifier.py                 TokenVerifier RS256 (iss, aud, exp, nbf, révocation)
│               ├── jwks.py                     résolution JWKS avec cache et anti-martèlement
│               ├── revocation.py               synchronisation du flux de révocation
│               ├── service_token.py            client client_credentials avec cache
│               ├── resource_server.py          L3  assemblage JWKS + révocation + vérificateur + santé
│               └── rbac.py                     dépendances FastAPI authenticate / require_roles()
├── services/
│   ├── auth-service/                           ✅  L2
│   │   ├── Dockerfile                          multi-stage (builder / test / runtime), non-root uid 10001
│   │   ├── requirements.txt · requirements-dev.txt · pyproject.toml
│   │   ├── app/
│   │   │   ├── main.py · container.py          application et racine de composition
│   │   │   ├── core/          config.py · keys.py · db.py · passwords.py
│   │   │   ├── domain/        models.py · policies.py · errors.py
│   │   │   ├── repositories/  principals.py · refresh_tokens.py · revocations.py · audit.py
│   │   │   ├── services/      authentication.py · client_credentials.py · principals.py · tokens.py · bootstrap.py · maintenance.py
│   │   │   └── api/           routes_auth · routes_oauth · routes_tokens · routes_internal · routes_admin · routes_health · schemas · errors · cookies · deps
│   │   └── tests/
│   │       ├── unit/          29 tests (jetons, clés, politiques, Argon2, ra_common)
│   │       └── e2e/           15 scénarios contre le service réel
│   ├── payment-api/                            ✅  L3
│   │   ├── Dockerfile                          multi-stage (builder / test / runtime), non-root uid 10001
│   │   ├── requirements.txt · requirements-dev.txt · pyproject.toml
│   │   ├── app/
│   │   │   ├── main.py · container.py · observability.py
│   │   │   ├── core/          config.py
│   │   │   ├── domain/        models.py · money.py · policies.py · errors.py
│   │   │   ├── repositories/  accounts.py · transactions.py · operations.py (flags, intégrité, maintenance)
│   │   │   ├── services/      transactions.py · integrity.py · administration.py · runtime_flags.py · events.py · rate_limit.py · faults.py
│   │   │   └── api/           routes_accounts · routes_transactions · routes_stream · routes_health · routes_admin · routes_lab · fault_middleware · schemas · errors · deps
│   │   └── tests/
│   │       ├── unit/          28 tests (montants, écriture, visibilité, quotas, tickets et diffusion SSE)
│   │       └── e2e/           22 scénarios (cycle de vie, idempotence, double dépense concurrente, quarantaine, SSE, attaque/réparation, pannes)
│   └── remediation-engine/                     ✅  L4
│       ├── Dockerfile                          multi-stage, non-root uid 10001, commande ra-ctl
│       ├── requirements.txt · requirements-dev.txt · pyproject.toml
│       ├── app/
│       │   ├── main.py                         un processus, 2 serveurs uvicorn (CONTROL / SUPERVISION), signaux centralisés
│       │   ├── apps.py · container.py · observability.py · cli.py (ra-ctl)
│       │   ├── core/          config.py
│       │   ├── domain/        models.py (états, transitions) · phase.py · playbooks.py · security.py (HMAC, empreinte)
│       │   ├── repositories/  incidents.py · runs.py (exécutions, vérifications) · observations.py (santé, phases, playbooks)
│       │   ├── connectors/    base.py · docker.py · platform.py (payment, auth, sondes) · registry.py (allowlist d'actions)
│       │   ├── services/      intake.py · orchestrator.py · runner.py · verifier.py (STM V1→V9) · monitor.py (santé, STM planifiée, watchdog) · phases.py · queries.py · events.py
│       │   ├── api/           control.py · supervision.py · common.py · schemas.py
│       │   └── tools/         simulate_alert.py (simulateur de détecteur)
│       └── tests/
│           ├── unit/          17 tests (signature, empreinte, transitions, phases, playbooks, Docker, STM simulée)
│           └── e2e/           12 scénarios (isolation, webhook, RBAC/SSE, suppression, intégrité, redémarrage, identifiants, escalade, watchdog)
└── frontend-dashboard/                         ✅  L5
    ├── Dockerfile                              deps → test (tsc + vitest) → build → nginx-unprivileged (uid 101)
    ├── package.json · package-lock.json · tsconfig.json · vite.config.ts · tailwind.config.ts
    ├── nginx/
    │   ├── default.conf.template               passerelle : liste blanche, SSE, auth_request, problem+json, journal JSON
    │   ├── snippets/                           security-headers.conf (CSP stricte) · proxy.conf · sse.conf
    │   └── 40-lab-routes.sh                    route du laboratoire générée seulement si CHAOS_LAB_ENABLED=true
    ├── src/
    │   ├── api/            http.ts (jeton en mémoire, refresh sur 401, RFC 9457) · endpoints.ts · types.ts
    │   ├── auth/           AuthProvider (restauration par cookie HttpOnly, renouvellement anticipé)
    │   ├── hooks/          useEventStream (ticket → EventSource, reconnexion + resync) · useDebounced
    │   ├── lib/            format.ts · status.ts (ton + icône + libellé) · timeline.ts (géométrie de la frise)
    │   ├── components/     ui.tsx (primitives) · Layout.tsx
    │   └── features/
    │       ├── payments/   comptes, paiement unitaire idempotent, générateur de flux, liste temps réel, détail
    │       ├── supervision/ bandeau Avant/Pendant/Après, frise, santé, incident, journal pas-à-pas, V1→V9, fil d'événements, laboratoire
    │       └── assistant/  conversation RAG avec contexte d'incident, mode dégradé explicite
    ├── tests/gateway/      28 tests de la passerelle depuis le réseau edge (pytest)
    └── e2e/                5 scénarios Playwright (Chromium) dont la boucle attaque → rétabli
```

## 4. Segmentation réseau et flux autorisés

Tous les réseaux sont `internal: true` (aucune sortie Internet) sauf `edge`.

| Réseau | Membres | Justification |
|---|---|---|
| `edge` | frontend-dashboard | Seul port publié, sur `127.0.0.1:${FRONTEND_PUBLIC_PORT:-8088}` en local (TLS terminé en amont en production) |
| `app` | frontend-dashboard, auth-service, payment-api, remediation-engine (:8002 + client sortant), RAG | Trafic métier et supervision |
| `control` | remediation-engine (:8001), moteur de détection | Webhook d'alertes et pilotage, isolés de la passerelle |
| `docker-ctl` | remediation-engine, socket-proxy | Seul chemin vers le démon Docker |
| `data` | auth-service, payment-api, remediation-engine | Sortie NAT vers la base externe (DB_HOST) ; base non joignable depuis la passerelle |
| `observability` | payment-api, auth-service, remediation-engine, Prometheus/Loki (autre lot) | Scrape `/metrics`, collecte de logs |

**Plan d'adressage** (adresses fixes, nécessaires au lien d'un listener à un seul réseau) :

| Réseau | Sous-réseau | Adresses fixes |
|---|---|---|
| `app` | 172.30.10.0/24 | remediation-engine (SUPERVISION) .10 · auth-service .20 · payment-api .30 · frontend-dashboard .50 |
| `control` | 172.30.20.0/24 | remediation-engine (CONTROL) .10 |
| `data` | 172.30.30.0/24 | (base externe : DB_HOST) |
| `docker-ctl` | 172.30.40.0/24 | remediation-engine .10 · socket-proxy .20 |

Conséquence vérifiée par les tests : un conteneur présent sur `app` **et** `control` qui résout `remediation-engine` obtient l'adresse du réseau `app`, où le port 8001 n'existe pas (connexion refusée). Les clients du webhook doivent donc cibler l'adresse du réseau `control` (`172.30.20.10:8001`), seule exposition du listener d'orchestration.

**Allowlist de la passerelle** (tout le reste → `404`) :

| Préfixe public | Cible interne | Remarque |
|---|---|---|
| `/api/auth/v1/` | `auth-service:8000/v1/` | `/internal/*` jamais routé |
| `/api/payment/v1/` | `payment-api:8000/v1/` | `/admin/*`, `/health/*`, `/metrics` jamais routés |
| `/api/payment/lab/v1/` | `payment-api:8000/lab/v1/` | Routé **uniquement** si `CHAOS_LAB_ENABLED=true` |
| `/api/supervision/v1/` | `remediation-engine:8002/v1/` | Lecture seule |
| `/api/assistant/v1/` | `${ASSISTANT_UPSTREAM_URL}` | Protégé par `auth_request` → `auth-service /internal/v1/authz/check?role=noc.viewer` ; le jeton utilisateur n'est **pas** transmis à l'agent (seuls `X-Auth-Sub` / `X-Auth-Roles`) ; agent absent → `503 ASSISTANT_UNAVAILABLE` |

## 5. Modèle de sécurité

### 5.1 Jetons

| Élément | Choix |
|---|---|
| Algorithme | **RS256**, clé privée PEM injectée par `AUTH_JWT_PRIVATE_KEY_PEM_B64`, `kid` = `AUTH_JWT_KEY_ID` ; rotation via `AUTH_JWT_PREVIOUS_PUBLIC_KEYS` (`kid:base64(PEM)`, séparés par des virgules) publiées dans le JWKS |
| Validation | Locale dans chaque resource server (JWKS en cache, rafraîchi toutes les 10 min ou sur `kid` inconnu) |
| Révocation | Flux `GET /internal/v1/revocations?since=` interrogé toutes les **5 s** ⇒ latence de révocation ≤ 5 s ; révocation unitaire (`jti`) ou globale par principal (`not_before`) |
| Durées | Access humain 5 min · access service 5 min · refresh 8 h (absolu, par famille) |
| Refresh SPA | Cookie `ra_refresh` `HttpOnly; Secure; SameSite=Strict; Path=/api/auth/v1/auth`, rotation à chaque usage, **réutilisation ⇒ révocation de toute la famille** |
| Access SPA | Conservé en mémoire uniquement (jamais `localStorage`) |
| SSE | `EventSource` ne transmet pas d'en-tête : ticket opaque à usage unique, durée 30 s, obtenu par `POST …/stream-tickets` authentifié |

Claims d'un jeton d'accès :

```json
{
  "iss": "https://auth.resilience-alpha.local",
  "sub": "00000000-0000-4000-8000-000000000002",
  "aud": ["payment-api", "remediation-supervision", "assistant"],
  "iat": 1792396800, "nbf": 1792396800, "exp": 1792397100,
  "jti": "5b0c6c0e-4a3e-4d8c-9f5e-0a2f7b6d9c11",
  "typ": "access",
  "pkind": "USER",
  "name": "Alice Démo",
  "roles": ["payment.customer"]
}
```

### 5.2 Matrice RBAC

| Rôle | Type | Portail métier | Supervision (lecture) | Assistant | Admin payment | Admin auth | Webhook alertes | Pilotage remédiation | Lab chaos |
|---|---|---|---|---|---|---|---|---|---|
| `payment.customer` | USER | ses comptes | – | – | – | – | – | – | – |
| `payment.operator` | USER | tous (lecture) | – | – | – | – | – | – | – |
| `noc.viewer` | USER | – | ✔ | ✔ | – | – | – | – | – |
| `remediation.admin` | USER | – | ✔ | ✔ | – | – | – | ✔ (CONTROL) | – |
| `auth.admin` | USER | – | – | – | – | ✔ | – | – | – |
| `chaos.operator` | USER | – | – | – | – | – | – | – | ✔ (si activé) |
| `svc.remediation` | SERVICE | – | – | – | ✔ | révocation / désactivation | – | – | – |
| `svc.synthetic` | SERVICE | comptes RA-9xxx | – | – | – | – | – | – | – |
| `svc.detector` | SERVICE | – | – | – | – | – | ✔ | – | – |
| `svc.resource_server` | SERVICE | – | – | – | – | flux de révocation | – | – | – |

Séparation stricte : les opérations métier (`payment.*`) et les opérations de remédiation (`svc.remediation`, `remediation.admin`) n'ont **aucun recouvrement** ; un rôle `svc.*` ne peut techniquement pas être attribué à un humain (contrainte en base, SQLSTATE `RA101`).

### 5.3 Moindre privilège — synthèse

* **Base** : un compte MariaDB par service, cloisonné à sa base ; `ra_payment_app` n'a ni `UPDATE` sur les soldes ni `INSERT` sur le grand livre (tout passe par `sp_execute_transaction`) ; les procédures de réparation ne sont exécutables que par `ra_payment_maint`, utilisé uniquement par les routes `/admin`.
* **Docker** : le moteur ne voit jamais `/var/run/docker.sock` ; le proxy n'autorise que `POST /containers/{auth-service|payment-api}/restart` et `GET /containers/json` ; le moteur vérifie en plus le label `resilience.remediable=true`.
* **Webhook** : JWT `svc.detector` **et** signature HMAC-SHA256 horodatée (fenêtre 300 s, anti-rejeu par `external_id`).
* **Conteneurs** : utilisateur non-root, `read_only: true`, `cap_drop: [ALL]`, `no-new-privileges`, `tmpfs` pour `/tmp`.
* **Secrets** : uniquement via variables d'environnement (cf. `.env.example`) ; aucune valeur par défaut exploitable dans le code — le service refuse de démarrer si un secret requis est absent ou trop court.

## 6. Conventions transverses (12-Factor)

| Sujet | Convention |
|---|---|
| Versionnement d'API | Préfixe `/v1` ; rupture ⇒ `/v2` en parallèle |
| Erreurs | RFC 9457 `application/problem+json` avec `type`, `title`, `status`, `detail`, `instance`, `code`, `correlation_id`, `errors[]` |
| Corrélation | `X-Request-ID` (généré si absent) et `traceparent` W3C propagés ; `X-Correlation-ID` porte l'`incident_id` lors des actions de remédiation et du STM |
| Idempotence | En-tête `Idempotency-Key` obligatoire sur `POST /v1/transactions` ; rejeu ⇒ même réponse + `Idempotent-Replayed: true` |
| Pagination | Curseur opaque : `?limit=50&cursor=…` ⇒ `{ "items": [], "next_cursor": "…" | null }` |
| Montants | Chaîne décimale en entrée/sortie (`"125.50"`) + `minor_units` entier ; jamais de flottant |
| Dates | ISO 8601 UTC (`2026-10-19T08:15:30.123Z`) |
| Santé | `application/health+json` (draft IETF `inadarei-api-health-check`) : `status` ∈ `pass` / `warn` / `fail` |
| Logs | JSON une ligne par événement sur stdout (voir § 7) |
| Configuration | Variables d'environnement préfixées par service (`AUTH_`, `PAYMENT_`, `REMEDIATION_`, `FRONTEND_`) |

## 7. Observabilité

**Format de log (tous services)** :

```json
{
  "ts": "2026-10-19T08:15:30.123Z",
  "level": "INFO",
  "service": "payment-api",
  "version": "1.0.0",
  "event": "transaction.executed",
  "message": "transaction executed",
  "request_id": "0f8b7a3e-…",
  "trace_id": "4bf92f3577b34da6a3ce929d0e0e4736",
  "span_id": "00f067aa0ba902b7",
  "correlation_id": "inc-…",
  "principal_id": "00000000-0000-4000-8000-000000000002",
  "http": { "method": "POST", "route": "/v1/transactions", "status": 201, "duration_ms": 18.4 },
  "attributes": { "transaction_id": "…", "amount_minor": 12550, "currency": "EUR", "synthetic": false }
}
```

Aucune donnée sensible n'est journalisée (mots de passe, jetons, `client_secret`, en-têtes `Authorization`/`Cookie` masqués par le middleware).

**Métriques Prometheus `payment-api`** (préfixe `ra_`) :

| Métrique | Type | Labels |
|---|---|---|
| `ra_http_requests_total` | counter | `method`, `route`, `status` |
| `ra_http_request_duration_seconds` | histogram | `method`, `route` |
| `ra_transactions_total` | counter | `status`, `synthetic` |
| `ra_transaction_processing_seconds` | histogram | `outcome` |
| `ra_transaction_amount_minor_total` | counter | `currency` |
| `ra_idempotent_replays_total` | counter | — |
| `ra_integrity_check_passed` | gauge (0/1) | `check` |
| `ra_ledger_divergence_total` | counter | — (SQLSTATE `RA009` intercepté) |
| `ra_write_mode` | gauge | `mode` |
| `ra_db_pool_connections` | gauge | `state` (`in_use`, `idle`) |
| `ra_auth_rejections_total` | counter | `reason` (`expired`, `revoked`, `forbidden`…) |

`remediation-engine` expose `ra_incidents_total{category,outcome}`, `ra_remediation_duration_seconds{playbook}`, `ra_verification_runs_total{status}`, `ra_mttr_seconds` (histogram), `ra_system_phase{phase}`.
