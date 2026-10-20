# 03 — Contrats d'interface

> Ces contrats font foi pour les Lots 2 à 5. Les schémas OpenAPI 3.1 générés par FastAPI (`/openapi.json`, désactivé en production) devront leur être conformes ; les écarts seront traités comme des anomalies.
> Contrats inter-lots formalisés en JSON Schema : [contracts/alert-webhook.schema.json](../contracts/alert-webhook.schema.json), [contracts/sse-events.schema.json](../contracts/sse-events.schema.json).

## 0. Conventions communes

### 0.1 Adresses

| Consommateur | auth-service | payment-api | remediation CONTROL | remediation SUPERVISION |
|---|---|---|---|---|
| Navigateur (via passerelle) | `/api/auth` | `/api/payment` | ✖ | `/api/supervision` |
| Services internes | `http://auth-service:8000` | `http://payment-api:8000` | `http://remediation-engine:8001` | `http://remediation-engine:8002` |

Dans la suite, les chemins sont donnés **côté service** (ex. `/v1/transactions`) ; la passerelle les publie sous le préfixe correspondant (ex. `/api/payment/v1/transactions`).

### 0.2 En-têtes

| En-tête | Sens | Règle |
|---|---|---|
| `Authorization: Bearer <jwt>` | requête | Obligatoire sauf mention *public* |
| `X-Request-ID` | requête/réponse | UUID ; généré par la passerelle s'il est absent, renvoyé tel quel |
| `traceparent` | requête | W3C Trace Context, propagé de service en service |
| `X-Correlation-ID` | requête | `incident_id` pour toute action initiée par la remédiation et pour le STM |
| `Idempotency-Key` | requête | Obligatoire sur `POST /v1/transactions` — `^[A-Za-z0-9_:.-]{8,64}$` |
| `Idempotent-Replayed: true` | réponse | Présent si la réponse est un rejeu |
| `X-RA-Signature` | requête | Webhook d'alertes uniquement (§ 3.1) |
| `Retry-After` | réponse | Sur `429` et `503` |

### 0.3 Format d'erreur — RFC 9457

```http
HTTP/1.1 422 Unprocessable Content
Content-Type: application/problem+json
```

```json
{
  "type": "https://errors.resilience-alpha.local/validation-error",
  "title": "Validation error",
  "status": 422,
  "detail": "Request body failed validation",
  "instance": "/v1/transactions",
  "code": "VALIDATION_ERROR",
  "correlation_id": "0f8b7a3e-2a1c-4b7e-9d34-6f1e2c3b4a5d",
  "errors": [
    { "location": "body.amount.value", "message": "must have at most 2 decimal places for EUR" }
  ]
}
```

### 0.4 Catalogue des codes d'erreur

| HTTP | `code` | Signification |
|---|---|---|
| 400 | `MALFORMED_REQUEST` | JSON illisible, en-tête mal formé |
| 401 | `UNAUTHENTICATED` | Jeton absent, invalide, expiré ou révoqué (`WWW-Authenticate: Bearer error="invalid_token"`) |
| 401 | `INVALID_CREDENTIALS` | Identifiants incorrects (message volontairement générique) |
| 401 | `INVALID_SIGNATURE` | Signature HMAC du webhook absente/invalide/expirée |
| 403 | `FORBIDDEN` | Rôle insuffisant ou ressource d'un autre principal |
| 403 | `CSRF_PROTECTION` | En-tête `X-Requested-With: ra-dashboard` absent sur `/v1/auth/refresh` |
| 403 | `ACCOUNT_LOCKED` | Verrouillage temporaire après échecs successifs |
| 404 | `NOT_FOUND` | Ressource inexistante **ou non visible** pour l'appelant |
| 409 | `IDEMPOTENCY_CONFLICT` | Même `Idempotency-Key`, payload différent |
| 409 | `INVALID_STATE` | Opération incompatible avec l'état courant |
| 409 | `REFRESH_TOKEN_REUSED` | Réutilisation détectée — famille révoquée |
| 409 | `LEDGER_COMPROMISED` | Chaîne de hachage du grand livre rompue : réparation automatique refusée (`RA012`) |
| 409 | `LAB_PRIMITIVES_MISSING` | Base initialisée sans `CHAOS_LAB_ENABLED=true` |
| 422 | `VALIDATION_ERROR` | Validation Pydantic |
| 422 | `CURRENCY_MISMATCH` | Devise différente de celle des comptes |
| 422 | `SYNTHETIC_SEGREGATION` | Mélange comptes réels / synthétiques |
| 422 | `AMOUNT_LIMIT_EXCEEDED` | Au-delà de `max_transaction_amount_minor` |
| 429 | `RATE_LIMITED` | Au-delà de `max_requests_per_minute_per_principal` |
| 503 | `WRITE_MODE_RESTRICTED` | Plateforme en `READ_ONLY` (toute écriture, y compris synthétique) ou `SYNTHETIC_ONLY` (quarantaine : seul `svc.synthetic` écrit) |
| 503 | `DEPENDENCY_UNAVAILABLE` | Base ou service amont indisponible |
| 500 | `INTERNAL_ERROR` | Erreur non prévue (aucun détail interne exposé) |

Codes métier portés par une transaction `REJECTED`/`FAILED` (champ `failure.code`) : `INSUFFICIENT_FUNDS`, `ACCOUNT_NOT_ACTIVE`, `LEDGER_INTEGRITY_FAULT`, `STALE_PURGED`, `INTERNAL_ERROR`.

### 0.5 Objets communs

```jsonc
// Money — entrée et sortie
{ "value": "125.50", "currency": "EUR" }                 // entrée : chaîne décimale, ≤ minor_units décimales, > 0
{ "value": "125.50", "currency": "EUR", "minor": 12550 } // sortie

// Page
{ "items": [ /* … */ ], "next_cursor": "eyJjIjoiMjAyNi0xMC0xOVQwODoxNTozMFoiLCJpIjoiNWIwYyJ9" }
```

---

## 1. auth-service

### 1.1 Récapitulatif

| Méthode | Chemin | Accès | Exposé passerelle |
|---|---|---|---|
| POST | `/v1/auth/login` | public | ✔ |
| POST | `/v1/auth/refresh` | cookie `ra_refresh` | ✔ |
| POST | `/v1/auth/logout` | Bearer | ✔ |
| GET | `/v1/me` | Bearer | ✔ |
| POST | `/v1/oauth/token` | `client_id` + `client_secret` | ✖ |
| GET | `/.well-known/jwks.json` | public (réseau interne) | ✖ |
| POST | `/v1/tokens/revoke` | Bearer (soi-même) ou `auth.admin` | ✔ |
| POST | `/v1/tokens/introspect` | `svc.resource_server` | ✖ |
| GET | `/internal/v1/revocations` | `svc.resource_server` | ✖ |
| GET | `/internal/v1/authz/check` | Bearer de l'utilisateur (sous-requête nginx) | ✖ |
| POST | `/internal/v1/principals/{id}/revoke-tokens` | `svc.remediation` ou `auth.admin` | ✖ |
| POST | `/internal/v1/principals/{id}/disable` | `svc.remediation` ou `auth.admin` | ✖ |
| POST | `/internal/v1/principals/{id}/enable` | `auth.admin` **uniquement** (humain) | ✖ |
| GET | `/v1/admin/principals` | `auth.admin` | ✔ |
| GET | `/health/liveness` · `/health/readiness` | public (réseau interne) | ✖ |

### 1.2 `POST /v1/auth/login`

```json
{ "username": "alice", "password": "<saisi par l'utilisateur>" }
```

`200 OK` + `Set-Cookie: ra_refresh=<opaque>; HttpOnly; Secure; SameSite=Strict; Path=/api/auth/v1/auth; Max-Age=28800`

```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6InJhLTIwMjYtMTAiLCJ0eXAiOiJKV1QifQ…",
  "token_type": "Bearer",
  "expires_in": 300,
  "principal": {
    "id": "00000000-0000-4000-8000-000000000002",
    "username": "alice",
    "display_name": "Alice Démo",
    "kind": "USER",
    "roles": ["payment.customer"]
  }
}
```

Erreurs : `401 INVALID_CREDENTIALS`, `403 ACCOUNT_LOCKED` (après 5 échecs ⇒ 15 min, `Retry-After`), `422`.
Le temps de réponse est rendu constant (vérification Argon2 factice si l'utilisateur n'existe pas) pour éviter l'énumération.

### 1.3 `POST /v1/auth/refresh`

Corps vide, cookie `ra_refresh` requis, en-tête `X-Requested-With: ra-dashboard` requis (anti-CSRF complémentaire). Réponse identique à `/login` (nouveau cookie, ancien marqué `used_at`).
Erreurs : `401 UNAUTHENTICATED`, `409 REFRESH_TOKEN_REUSED` (toute la famille est révoquée et un événement d'audit `REFRESH_TOKEN_REUSE` émis).

### 1.4 `POST /v1/auth/logout`

`204 No Content` — révoque la famille de refresh et le `jti` du jeton d'accès courant ; efface le cookie.

### 1.5 `GET /v1/me`

`200` — objet `principal` (cf. 1.2) + `"token_expires_at": "2026-10-19T08:20:30Z"`.

### 1.6 `POST /v1/oauth/token` — M2M (RFC 6749 § 4.4)

`Content-Type: application/x-www-form-urlencoded`

```text
grant_type=client_credentials&client_id=svc-synthetic&client_secret=<env>&audience=payment-api
```

`200`

```json
{ "access_token": "eyJ…", "token_type": "Bearer", "expires_in": 300, "scope": "svc.synthetic" }
```

Erreurs au format RFC 6749 (pas problem+json) : `400 {"error":"unsupported_grant_type"}`, `401 {"error":"invalid_client"}`, `400 {"error":"invalid_target"}` si l'audience n'est pas autorisée pour ce client.

Audiences autorisées :

| Client | Audiences |
|---|---|
| `svc-remediation` | `payment-api`, `auth-service` |
| `svc-synthetic` | `payment-api` |
| `svc-detector` | `remediation-control` |
| `svc-payment-api` | `auth-service` |

### 1.7 `GET /.well-known/jwks.json`

```json
{
  "keys": [
    { "kty": "RSA", "use": "sig", "alg": "RS256", "kid": "ra-2026-10", "n": "0vx7agoebGcQSuu…", "e": "AQAB" }
  ]
}
```

`Cache-Control: public, max-age=600`.

### 1.8 `POST /v1/tokens/revoke`

```json
{ "jti": "5b0c6c0e-4a3e-4d8c-9f5e-0a2f7b6d9c11", "reason": "USER_REQUEST" }
```

`204`. Un `payment.customer` ne peut révoquer que ses propres jetons ; sinon `403`.

### 1.9 `POST /v1/tokens/introspect` (RFC 7662)

Formulaire `token=<jwt>` → `200 {"active": true, "sub": "…", "roles": [...], "exp": 1792397100, "jti": "…", "pkind": "USER"}` ou `{"active": false}`.

### 1.10 `GET /internal/v1/revocations?since=<seq>&limit=500`

```json
{
  "cursor": 1842,
  "items": [
    { "seq": 1841, "kind": "JTI", "jti": "5b0c6c0e-…", "expires_at": "2026-10-19T08:20:30Z" },
    { "seq": 1842, "kind": "PRINCIPAL", "principal_id": "00000000-0000-4000-8000-000000000003",
      "not_before": "2026-10-19T08:16:02Z", "expires_at": "2026-10-19T08:21:02Z" }
  ]
}
```

Règle côté resource server : rejeter si `jti` ∈ ensemble révoqué **ou** si `iat < not_before(sub)`. `since=0` ⇒ instantané complet des entrées non expirées. Les `iat` JWT étant des secondes entières, `not_before` est arrondi à la seconde **suivante** : tout jeton émis avant la révocation est invalidé ; un nouveau jeton est accepté au plus 1 s après. Implémentation de référence : `ra_common.security.revocation.RevocationFeed`.

### 1.11 `GET /internal/v1/authz/check?role=noc.viewer`

Sous-requête `auth_request` de nginx (en-tête `Authorization` transmis) : `204` (en-têtes `X-Auth-Sub`, `X-Auth-Roles` renvoyés à l'amont), `401`, `403`.

### 1.12 `POST /internal/v1/principals/{id}/revoke-tokens` · `/disable`

```json
{ "reason": "CREDENTIAL_COMPROMISE", "incident_id": "c7d1b3f4-8a7e-4f3a-9a8e-2d1b0c9e8f7a" }
```

`200`

```json
{
  "principal_id": "00000000-0000-4000-8000-000000000003",
  "is_active": false,
  "tokens_valid_after": "2026-10-19T08:16:02Z",
  "refresh_tokens_revoked": 2
}
```

Garde-fous : `svc.remediation` ne peut ni désactiver un principal `SERVICE`, ni le principal `admin` (`403`) — empêche le moteur de s'auto-neutraliser ou de verrouiller l'administration. Idempotent (rappel ⇒ même résultat).

---

## 2. payment-api

### 2.1 Récapitulatif

| Méthode | Chemin | Rôles | Exposé |
|---|---|---|---|
| GET | `/v1/accounts` | `payment.customer` (siens), `payment.operator`, `svc.synthetic` (RA-9xxx) | ✔ |
| GET | `/v1/accounts/{id}` | idem | ✔ |
| GET | `/v1/accounts/{id}/ledger` | idem | ✔ |
| POST | `/v1/transactions` | `payment.customer`, `svc.synthetic` | ✔ |
| POST | `/v1/transactions/batch` | `payment.customer` | ✔ |
| GET | `/v1/transactions` | `payment.customer` (siennes), `payment.operator`, `svc.synthetic` | ✔ |
| GET | `/v1/transactions/{id}` | idem | ✔ |
| POST | `/v1/transactions/{id}/execute` | initiateur | ✔ |
| POST | `/v1/transactions/{id}/cancel` | initiateur | ✔ |
| POST | `/v1/stream-tickets` | tout rôle `payment.*` | ✔ |
| GET | `/v1/transactions/events?ticket=` | ticket | ✔ (SSE) |
| GET | `/health/liveness` | public (interne) | ✖ |
| GET | `/health/readiness` | public (interne) | ✖ |
| GET | `/health/integrity` | `svc.remediation`, `svc.synthetic` | ✖ |
| GET | `/metrics` | réseau `observability` | ✖ |
| GET | `/admin/v1/runtime-flags` | `svc.remediation` | ✖ |
| PUT | `/admin/v1/runtime-flags/{key}` | `svc.remediation` | ✖ |
| POST | `/admin/v1/integrity/reports` | `svc.remediation` | ✖ |
| POST | `/admin/v1/integrity/repair` | `svc.remediation` | ✖ |
| POST | `/admin/v1/maintenance/purge-stale` | `svc.remediation` | ✖ |
| POST | `/admin/v1/accounts/{id}/freeze` · `/unfreeze` | `svc.remediation` | ✖ |
| GET/POST/DELETE | `/lab/v1/faults` | `chaos.operator` — **404 si `CHAOS_LAB_ENABLED≠true`** | ✔ si activé |

### 2.2 Ressource `Transaction`

```json
{
  "id": "7a1f3154-90dd-4d16-85c7-10549dbc34d4",
  "status": "EXECUTED",
  "debit_account":  { "id": "10000000-0000-4000-8000-000000000001", "account_number": "RA-1000-0001" },
  "credit_account": { "id": "10000000-0000-4000-8000-000000000003", "account_number": "RA-1000-0003" },
  "amount": { "value": "125.50", "currency": "EUR", "minor": 12550 },
  "description": "Facture démo #42",
  "is_synthetic": false,
  "failure": null,
  "idempotency_key": "b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d",
  "created_at":   "2026-10-19T08:15:30.101Z",
  "validated_at": "2026-10-19T08:15:30.109Z",
  "executed_at":  "2026-10-19T08:15:30.118Z",
  "history": [
    { "status": "PENDING",   "at": "2026-10-19T08:15:30.101Z" },
    { "status": "VALIDATED", "at": "2026-10-19T08:15:30.109Z" },
    { "status": "EXECUTED",  "at": "2026-10-19T08:15:30.118Z" }
  ]
}
```

`failure` non nul ⇒ `{ "code": "INSUFFICIENT_FUNDS", "reason": "available balance lower than requested amount" }`. `history` n'est présent que sur `GET /v1/transactions/{id}`.

### 2.3 `POST /v1/transactions`

```http
POST /v1/transactions
Authorization: Bearer eyJ…
Idempotency-Key: b3f1c2d4-5e6f-4a7b-8c9d-0e1f2a3b4c5d
Content-Type: application/json
```

```json
{
  "debit_account_id": "10000000-0000-4000-8000-000000000001",
  "credit_account_number": "RA-1000-0003",
  "amount": { "value": "125.50", "currency": "EUR" },
  "description": "Facture démo #42",
  "auto_execute": true
}
```

| Champ | Contrainte |
|---|---|
| `debit_account_id` | UUID d'un compte **appartenant à l'appelant** (sinon `404`) |
| `credit_account_number` | `^RA-[0-9]{4}-[0-9]{4}$`, compte existant (sinon `422`) |
| `amount.value` | décimal > 0, précision ≤ `minor_units`, ≤ `max_transaction_amount_minor` |
| `amount.currency` | identique aux deux comptes |
| `description` | ≤ 140 caractères, optionnel |
| `auto_execute` | défaut `true` ; `false` ⇒ s'arrête en `VALIDATED` (exécution via `/execute`) |

Traitement (une seule transaction SQL) : contrôle `write_mode` → insertion `PENDING` → contrôles métier → `VALIDATED` | `REJECTED` → `fn_execute_transaction` si `auto_execute` → `EXECUTED` | `REJECTED`.

| Réponse | Cas |
|---|---|
| `201 Created` + `Location` | Transaction créée (y compris si `REJECTED` : le refus métier est un résultat historisé, pas une erreur HTTP) |
| `200 OK` + `Idempotent-Replayed: true` | Même clé, même payload ⇒ ressource d'origine |
| `409 IDEMPOTENCY_CONFLICT` | Même clé, payload différent (`request_fingerprint` = SHA-256 du JSON canonique) |
| `422` | Validation, `CURRENCY_MISMATCH`, `SYNTHETIC_SEGREGATION`, `AMOUNT_LIMIT_EXCEEDED` |
| `429 RATE_LIMITED` | Bridage dynamique |
| `503 WRITE_MODE_RESTRICTED` | `READ_ONLY`, ou `SYNTHETIC_ONLY` pour un appelant non synthétique |

Divergence solde/grand livre détectée en base (`RA009`) : la transaction est historisée `FAILED / LEDGER_INTEGRITY_FAULT`, réponse `201` avec ce statut, métrique `ra_ledger_divergence_total` incrémentée, log `integrity.divergence_detected` (niveau `ERROR`).

Pour `svc.synthetic`, le corps est identique ; `is_synthetic` est déduit du principal (jamais fourni par le client) et seuls les comptes `RA-9xxx` sont acceptés.

### 2.4 `POST /v1/transactions/batch` — mode « flux »

```json
{
  "items": [
    { "idempotency_key": "flow-20261019-0001", "debit_account_id": "…", "credit_account_number": "RA-2000-0001",
      "amount": { "value": "9.99", "currency": "EUR" }, "description": "flux #1" }
  ]
}
```

1 à 50 éléments, chacun traité dans **sa propre** transaction SQL (pas d'atomicité globale). `207 Multi-Status` :

```json
{
  "results": [
    { "index": 0, "status": 201, "transaction": { "id": "…", "status": "EXECUTED" } },
    { "index": 1, "status": 422, "error": { "code": "CURRENCY_MISMATCH", "detail": "…" } }
  ]
}
```

### 2.5 Lecture

* `GET /v1/transactions?status=EXECUTED&account_id=<uuid>&synthetic=false&limit=50&cursor=…` → `Page<Transaction>` (tri `created_at DESC, id DESC`).
* `GET /v1/accounts` → `{ "items": [ { "id", "account_number", "holder_name", "currency", "status", "is_synthetic", "balance": Money, "updated_at" } ] }`.
* `GET /v1/accounts/{id}/ledger?limit=50&cursor=…` → `Page<{ "seq", "transaction_id", "direction", "amount": Money, "balance_after": Money, "entry_hash": "hex", "created_at" }>`.

### 2.6 `POST /v1/transactions/{id}/execute` · `/cancel`

Sans corps. `200` + `Transaction`. `409 INVALID_STATE` si l'état ne le permet pas. `execute` est idempotent sur une transaction déjà `EXECUTED`.

### 2.7 Flux temps réel des transactions (SSE)

1. `POST /v1/stream-tickets` → `201 {"ticket": "st_9fJ2…", "expires_in": 30}`. Le ticket est signé HMAC-SHA256 (`PAYMENT_STREAM_TICKET_SECRET`), porte le `sub`, les rôles et l'expiration du jeton d'accès : il est vérifiable par toute instance sans état partagé ; l'usage unique est garanti par instance.
2. `GET /v1/transactions/events?ticket=st_9fJ2…` → `text/event-stream` :

```text
id: 1842
event: transaction.updated
data: {"type":"transaction.updated","seq":1842,"occurred_at":"2026-10-19T08:15:30.118Z","payload":{"id":"7a1f…","status":"EXECUTED","amount":{"value":"125.50","currency":"EUR","minor":12550},"failure":null}}

: heartbeat
```

Événements : `transaction.created`, `transaction.updated`. Un client ne reçoit que les transactions qu'il a le droit de lire. Reprise via `Last-Event-ID` (tampon des 1 000 derniers événements ; au-delà, `stream.reset`).

Les événements sont émis par `pg_notify` **dans** la transaction SQL métier : PostgreSQL ne les délivre qu'au COMMIT (aucun événement fantôme pour une écriture annulée) et chaque instance les reçoit via une connexion `LISTEN` dédiée. Le flux est fermé par le serveur à l'expiration du jeton d'accès d'origine (`event: stream.expired`) ou dès sa révocation (`event: stream.revoked`) ; le client demande alors un nouveau ticket avec un jeton rafraîchi.

### 2.8 Endpoints de diagnostic

Format `application/health+json`. Codes : `200` si `pass`/`warn`, `503` si `fail`.

**`GET /health/liveness`** — processus vivant, boucle d'événements réactive (aucune dépendance externe).

```json
{ "status": "pass", "service": "payment-api", "version": "1.0.0", "releaseId": "git-3f2a1c9" }
```

**`GET /health/readiness`** — prêt à servir.

```json
{
  "status": "pass",
  "service": "payment-api",
  "version": "1.0.0",
  "checks": {
    "postgres:connectivity":  [{ "status": "pass", "observedValue": 3.2, "observedUnit": "ms", "time": "2026-10-19T08:15:30Z" }],
    "postgres:pool":          [{ "status": "pass", "observedValue": 0.15, "observedUnit": "ratio_in_use" }],
    "auth:jwks":              [{ "status": "pass", "observedValue": 312, "observedUnit": "s_since_refresh" }],
    "auth:revocation-feed":   [{ "status": "pass", "observedValue": 2.1, "observedUnit": "s_since_sync" }],
    "runtime:write-mode":     [{ "status": "pass", "observedValue": "READ_WRITE" }]
  }
}
```

Règles : `fail` si BDD injoignable, latence > 500 ms, JWKS jamais chargé ou flux de révocation non synchronisé depuis > 30 s ; `warn` si `write_mode ≠ READ_WRITE` ou pool > 80 %.

**`GET /health/integrity`** — cohérence des données **et** de la logique métier (`?refresh=true` pour ignorer le cache de 5 s ; limité à 6 appels/min/principal).

```json
{
  "status": "fail",
  "service": "payment-api",
  "report_id": "1d4c…",
  "generated_at": "2026-10-19T08:16:05Z",
  "duration_ms": 41,
  "checks": {
    "data:LEDGER_HASH_CHAIN":      [{ "status": "pass", "observedValue": 0, "observedUnit": "violations" }],
    "data:LEDGER_RUNNING_BALANCE": [{ "status": "pass", "observedValue": 0, "observedUnit": "violations" }],
    "data:BALANCE_MATCHES_LEDGER": [{ "status": "fail", "observedValue": 1, "observedUnit": "violations",
                                      "output": [{ "account_id": "10000000-…-0003", "actual_balance": 312550, "expected_balance": 262550 }] }],
    "data:DOUBLE_ENTRY":           [{ "status": "pass", "observedValue": 0, "observedUnit": "violations" }],
    "data:MONEY_CONSERVATION":     [{ "status": "fail", "observedValue": 1, "observedUnit": "violations" }],
    "data:SYNTHETIC_SEGREGATION":  [{ "status": "pass", "observedValue": 0, "observedUnit": "violations" }],
    "data:STALE_IN_FLIGHT":        [{ "status": "pass", "observedValue": 0, "observedUnit": "violations" }],
    "logic:dry-run-execution":     [{ "status": "pass", "observedValue": 6.8, "observedUnit": "ms" }]
  }
}
```

`logic:dry-run-execution` exécute une transaction synthétique complète (insertion, validation, `fn_execute_transaction`, `SET CONSTRAINTS ALL IMMEDIATE`) **dans une transaction SQL annulée** : prouve que les déclencheurs, la partie double et la chaîne de hachage fonctionnent, sans laisser de trace.

### 2.9 Administration de remédiation (`svc.remediation`, réseau interne)

Toutes les requêtes portent `X-Correlation-ID: <incident_id>` et un champ `reason` (5–256 caractères) tracé en base.

**`PUT /admin/v1/runtime-flags/{key}`** — `key` ∈ `write_mode`, `max_transaction_amount_minor`, `max_requests_per_minute_per_principal`.

```json
{ "value": "SYNTHETIC_ONLY", "reason": "PB-INTEGRITY-RESTORE step 1", "incident_id": "c7d1b3f4-…" }
```

`200 { "key": "write_mode", "previous_value": "READ_WRITE", "value": "SYNTHETIC_ONLY", "updated_at": "…" }`. Effet immédiat sur l'instance appelée, ≤ `PAYMENT_FLAGS_CACHE_SECONDS` (2 s) sur les autres. Le quota `max_requests_per_minute_per_principal` s'applique par instance aux principaux humains ; les comptes de service (sondes synthétiques, remédiation) en sont exemptés afin qu'un bridage ne bloque jamais la vérification de reprise.

**`POST /admin/v1/integrity/reports`** — `{ "incident_id": "…" }` → `201` + rapport (format § 2.8, persisté dans `integrity_reports`, `trigger_source = REMEDIATION`).

**`POST /admin/v1/integrity/repair`**

```json
{ "reason": "PB-INTEGRITY-RESTORE step 4", "incident_id": "c7d1b3f4-…", "dry_run": false }
```

`200`

```json
{
  "dry_run": false,
  "repaired": [
    { "account_id": "10000000-0000-4000-8000-000000000003", "field": "available_minor", "previous": "312550", "corrected": "262550" }
  ],
  "integrity_after": { "status": "pass", "report_id": "…" }
}
```

`409 LEDGER_COMPROMISED` (SQLSTATE `RA012`) si le grand livre lui-même est altéré ⇒ le moteur escalade.

**`POST /admin/v1/maintenance/purge-stale`** — `{ "older_than_seconds": 120, "reason": "…", "incident_id": "…" }` → `200 { "purged": 3 }`.

**`POST /admin/v1/accounts/{id}/freeze`** · **`/unfreeze`** — `{ "reason": "…", "incident_id": "…" }` → `200 { "id": "…", "status": "FROZEN" }` ; comptes `RA-9xxx` non gelables (`409`).

### 2.10 Laboratoire de pannes (`chaos.operator`, `CHAOS_LAB_ENABLED=true`)

`POST /lab/v1/faults`

```json
{ "type": "BALANCE_TAMPER", "params": { "account_number": "RA-1000-0003", "delta": "500.00" }, "duration_seconds": null }
```

| `type` | Effet | Signal attendu côté détection | Catégorie d'alerte |
|---|---|---|---|
| `LATENCY` | `params.ms` de latence ajoutée sur `/v1/*` | p95 latence ↑ | `PERFORMANCE_DEGRADATION` |
| `ERROR_RATE` | `params.ratio` de réponses 500 | taux 5xx ↑ | `PERFORMANCE_DEGRADATION` |
| `READINESS_FAILURE` | readiness en `fail` | probe KO | `SERVICE_UNAVAILABLE` |
| `CRASH` | arrêt du processus (code 1) | conteneur down | `SERVICE_UNAVAILABLE` |
| `POOL_EXHAUSTION` | connexions BDD retenues | pool 100 %, 503 | `RESOURCE_EXHAUSTION` |
| `BALANCE_TAMPER` | `fn_lab_tamper_balance` | `RA009`, rapport d'intégrité KO | `DATA_INTEGRITY_VIOLATION` |

`201 { "fault_id": "…", "type": "…", "active_until": "…" | null }` · `GET /lab/v1/faults` liste · `DELETE /lab/v1/faults` lève toutes les pannes actives. Les pannes en mémoire sont automatiquement levées par un redémarrage, ce qui rend `PB-SERVICE-RESTART` efficace.

---

## 3. remediation-engine — listener CONTROL (`:8001`, réseau `control`)

### 3.1 `POST /v1/alerts` — webhook du moteur de détection

**Authentification double, toutes deux obligatoires** :

1. `Authorization: Bearer <jwt>` — `aud = remediation-control`, rôle `svc.detector`.
2. `X-RA-Signature: t=1792396965,v1=<hex>` avec `v1 = HMAC-SHA256(REMEDIATION_WEBHOOK_HMAC_SECRET, "<t>.<corps brut>")`. Rejet si `|now − t| > 300 s` ou comparaison non constante.

Limites : corps ≤ 64 Kio, 120 requêtes/min/source.

Corps (JSON Schema : [contracts/alert-webhook.schema.json](../contracts/alert-webhook.schema.json)) :

```json
{
  "schema_version": "1.0",
  "source": "ml-anomaly-detector",
  "external_id": "det-20261019-000123",
  "detected_at": "2026-10-19T08:16:01.250Z",
  "category": "DATA_INTEGRITY_VIOLATION",
  "severity": "CRITICAL",
  "confidence": 0.97,
  "title": "Balance/ledger divergence detected on payment-api",
  "description": "ra_ledger_divergence_total increased by 3 in 30s; integrity probe failing",
  "target": {
    "service": "payment-api",
    "principal_id": null,
    "account_id": "10000000-0000-4000-8000-000000000003"
  },
  "fingerprint": null,
  "evidence": {
    "metric": "ra_ledger_divergence_total",
    "window_seconds": 30,
    "observed": 3,
    "baseline": 0
  },
  "labels": { "env": "demo", "detector_model": "isolation-forest-v4" }
}
```

Empreinte de déduplication : si `fingerprint` est nul, `sha256(category | target.service | target.principal_id | target.account_id)` en hexadécimal.

`202 Accepted`

```json
{
  "alert_id": "2c9e…",
  "incident_id": "c7d1b3f4-8a7e-4f3a-9a8e-2d1b0c9e8f7a",
  "deduplicated": false,
  "incident_status": "OPEN"
}
```

| Cas | Réponse |
|---|---|
| Nouvelle alerte, nouvel incident | `202`, `deduplicated: false` |
| Nouvelle alerte rattachée à un incident ouvert de même empreinte | `202`, `deduplicated: true` (sévérité de l'incident relevée si supérieure) |
| Rejeu même `source` + `external_id` | `200` + `Idempotent-Replayed: true`, même corps |
| Signature invalide / horodatage hors fenêtre | `401 INVALID_SIGNATURE` |
| `severity = INFO` ou `confidence < REMEDIATION_MIN_CONFIDENCE` | `202`, incident créé puis `SUPPRESSED` |

Le traitement est **asynchrone** : la réponse est émise dès la persistance ; l'orchestrateur prend le relais (cf. doc 04).

### 3.2 Pilotage (`remediation.admin`)

| Méthode | Chemin | Corps | Effet |
|---|---|---|---|
| GET | `/v1/incidents?status=&limit=&cursor=` | — | Liste |
| GET | `/v1/incidents/{id}` | — | Détail complet (cf. § 4.3) |
| POST | `/v1/incidents/{id}/retry` | `{ "reason": "…" }` | `ESCALATED → REMEDIATING` (nouvelle tentative) |
| POST | `/v1/incidents/{id}/verify` | `{ "reason": "…" }` | `ESCALATED → VERIFYING` après correction humaine ; clôture **seulement** si STM `PASSED` |
| GET | `/v1/playbooks` | — | Catalogue |
| PATCH | `/v1/playbooks/{code}` | `{ "enabled": false }` | Activation / désactivation |
| POST | `/v1/verifications` | `{ "reason": "…" }` | STM à la demande hors incident (`200 {run_id, status, failed_check}`) ; enregistrée en `SCHEDULED`, la base n'acceptant `MANUAL` que rattachée à un incident |

Ces routes ne sont **pas** disponibles sur le listener SUPERVISION ; l'opérateur y accède via la CLI intégrée (le mot de passe est demandé interactivement, ou lu dans `RA_CTL_PASSWORD`) :

```bash
docker compose exec remediation-engine ra-ctl --user admin incidents --status ESCALATED
docker compose exec remediation-engine ra-ctl --user admin show <incident-id>
docker compose exec remediation-engine ra-ctl --user admin verify <incident-id> --reason "ledger restored from backup"
docker compose exec remediation-engine ra-ctl --user admin playbook-disable PB-PERF-RECOVERY
```

Le listener CONTROL accepte les jetons d'audience `remediation-control` (détecteur) et `remediation-supervision` (humains) ; chaque route impose ensuite son rôle (`svc.detector` pour le webhook, `remediation.admin` pour le pilotage). Les clients doivent cibler l'adresse du réseau `control` (`http://172.30.20.10:8001`) : le nom `remediation-engine` peut résoudre vers l'adresse du réseau `app`, où ce listener n'existe pas.

**Simulateur de détecteur** (démonstrations sans le lot ML/SIEM) : `docker compose --profile tools run --rm detector-simulator --category DATA_INTEGRITY_VIOLATION --service payment-api` émet une alerte conforme, authentifiée (`svc-detector`) et signée HMAC.

---

## 4. remediation-engine — listener SUPERVISION (`:8002`, lecture seule)

Rôles : `noc.viewer` ou `remediation.admin`. Aucune méthode mutante hormis l'émission de tickets SSE et le préfixe `/v1/admin` (§4.6).

### 4.1 `GET /v1/overview`

```json
{
  "phase": "RECOVERING",
  "phase_since": "2026-10-19T08:16:03.010Z",
  "active_incident": {
    "id": "c7d1b3f4-8a7e-4f3a-9a8e-2d1b0c9e8f7a",
    "title": "Balance/ledger divergence detected on payment-api",
    "category": "DATA_INTEGRITY_VIOLATION",
    "severity": "CRITICAL",
    "status": "REMEDIATING",
    "playbook_code": "PB-INTEGRITY-RESTORE",
    "attempt": 1,
    "opened_at": "2026-10-19T08:16:01.400Z"
  },
  "services": [
    { "name": "auth-service", "status": "UP",       "latency_ms": 4,  "checked_at": "2026-10-19T08:16:05Z" },
    { "name": "payment-api",  "status": "DEGRADED", "latency_ms": 21, "checked_at": "2026-10-19T08:16:05Z", "detail": "write_mode=SYNTHETIC_ONLY" },
    { "name": "database",     "status": "UP",       "latency_ms": 2,  "checked_at": "2026-10-19T08:16:05Z" }
  ],
  "counters": { "open_incidents": 1, "resolved_24h": 4, "escalated_24h": 0, "mttr_p50_seconds": 38.5 },
  "last_verification": { "run_id": "…", "status": "PASSED", "finished_at": "2026-10-19T07:58:12Z" },
  "stream_seq": 9921
}
```

### 4.2 `GET /v1/timeline?from=2026-10-19T08:00:00Z&to=2026-10-19T09:00:00Z`

Segments de phase prêts à afficher en frise **Avant / Pendant / Après** :

```json
{
  "segments": [
    { "phase": "NOMINAL",    "from": "2026-10-19T08:00:00Z", "to": "2026-10-19T08:16:01Z", "incident_id": null },
    { "phase": "CRITICAL",   "from": "2026-10-19T08:16:01Z", "to": "2026-10-19T08:16:03Z", "incident_id": "c7d1…" },
    { "phase": "RECOVERING", "from": "2026-10-19T08:16:03Z", "to": "2026-10-19T08:16:41Z", "incident_id": "c7d1…" },
    { "phase": "RESTORED",   "from": "2026-10-19T08:16:41Z", "to": "2026-10-19T08:21:41Z", "incident_id": "c7d1…" },
    { "phase": "NOMINAL",    "from": "2026-10-19T08:21:41Z", "to": null,                    "incident_id": null }
  ],
  "markers": [
    { "at": "2026-10-19T08:16:01Z", "kind": "alert.received",         "label": "DATA_INTEGRITY_VIOLATION (0.97)" },
    { "at": "2026-10-19T08:16:38Z", "kind": "verification.completed", "label": "STM PASSED (9/9)" },
    { "at": "2026-10-19T08:16:41Z", "kind": "incident.closed",        "label": "RESOLVED en 40 s" }
  ]
}
```

### 4.3 `GET /v1/incidents` · `GET /v1/incidents/{id}`

Liste : `Page<IncidentSummary>`. Détail :

```json
{
  "id": "c7d1b3f4-…",
  "status": "RESOLVED",
  "resolution": "AUTOMATIC",
  "category": "DATA_INTEGRITY_VIOLATION",
  "severity": "CRITICAL",
  "title": "…",
  "target": { "service": "payment-api", "principal_id": null, "account_id": "10000000-…-0003" },
  "playbook": { "code": "PB-INTEGRITY-RESTORE", "version": 1 },
  "opened_at": "…", "remediation_started_at": "…", "verified_at": "…", "closed_at": "…",
  "mttr_seconds": 40.1,
  "alerts": [ { "id": "…", "source": "ml-anomaly-detector", "external_id": "…", "severity": "CRITICAL", "confidence": 0.97, "received_at": "…" } ],
  "transitions": [ { "from": null, "to": "OPEN", "at": "…", "reason": "alert received" } ],
  "executions": [
    {
      "id": "…", "attempt": 1, "status": "SUCCEEDED", "started_at": "…", "finished_at": "…",
      "steps": [
        { "phase": "REMEDIATION", "seq": 1, "action": "payment.set_write_mode", "target": "payment-api",
          "status": "SUCCEEDED", "duration_ms": 14, "output": { "previous_value": "READ_WRITE", "value": "SYNTHETIC_ONLY" } }
      ]
    }
  ],
  "verifications": [
    { "id": "…", "status": "PASSED", "started_at": "…", "finished_at": "…", "synthetic_transaction_ids": ["…", "…"],
      "checks": [ { "seq": 1, "code": "API_READINESS", "passed": true, "latency_ms": 12, "detail": {} } ] }
  ]
}
```

### 4.4 `GET /v1/services/health?window=15m`

`window` : `<n>m` ou `<n>h`, 24 h au plus ; un échantillon par service et par sondage (5 s), rétention 24 h.

```json
{ "series": [ { "service": "payment-api", "points": [ { "t": "…", "status": "UP", "latency_ms": 8 } ] } ] }
```

### 4.5 Flux temps réel — `POST /v1/stream-tickets` puis `GET /v1/stream?ticket=…`

Enveloppe commune (JSON Schema : [contracts/sse-events.schema.json](../contracts/sse-events.schema.json)) :

```text
id: 9922
event: remediation.step
data: {"type":"remediation.step","seq":9922,"occurred_at":"2026-10-19T08:16:04.120Z","incident_id":"c7d1…","payload":{…}}
```

| `event` | `payload` |
|---|---|
| `system.phase_changed` | `{ "phase", "previous", "reason" }` |
| `service.health` | `{ "service", "status", "latency_ms", "detail" }` (émis à chaque changement + toutes les 15 s) |
| `alert.received` | `{ "alert_id", "source", "category", "severity", "confidence", "title", "deduplicated" }` |
| `incident.opened` | `{ "title", "category", "severity", "target_service", "playbook_code" }` |
| `incident.status_changed` | `{ "from", "to", "reason", "attempt" }` |
| `remediation.step` | `{ "execution_id", "phase", "seq", "action", "target", "status", "duration_ms", "output", "error" }` |
| `verification.started` | `{ "run_id", "trigger_source", "planned_checks": ["API_READINESS", …] }` |
| `verification.check` | `{ "run_id", "seq", "code", "passed", "latency_ms", "detail" }` |
| `verification.completed` | `{ "run_id", "status", "failed_check", "synthetic_transaction_ids" }` |
| `incident.closed` | `{ "status": "RESOLVED" \| "SUPPRESSED", "resolution", "mttr_seconds" }` |

Commentaire `: heartbeat` toutes les 15 s ; reprise via `Last-Event-ID` (tampon de 1 000 événements ; au-delà, le client reçoit `event: stream.reset` et recharge `/v1/overview`).

### 4.6 Console d'administration — `/v1/admin/*` (`remediation.admin`, authentification forte obligatoire)

Écart assumé : les routes de pilotage du §3.2 sont aussi montées sous `/v1/admin` sur ce listener pour que la console web
(derrière la passerelle authentifiée) puisse agir sans exposer le réseau `control`. Mêmes contrôles de rôle et d'état.

| Route | Effet |
|---|---|
| `POST /v1/admin/incidents/{id}/verify` · `/retry` | `{reason}` (5–256), journalisé `operator <user>: …` |
| `POST /v1/admin/incidents/{id}/acknowledge` | incident `ESCALATED` uniquement ; publie `incident.acknowledged {by, reason}` |
| `GET/PATCH /v1/admin/playbooks[/{code}]` | liste ; `{enabled}` seul modifiable |
| `GET /v1/admin/audit?limit=` | transitions + étapes + acquittements, `actor: human \| automated` |
| `GET /v1/admin/settings` | réglages moteur en lecture seule (aucun secret) |
| `POST /v1/admin/simulate-alert` | `chaos.operator` + `CHAOS_LAB_ENABLED=true`, sinon 404 |

Côté auth-service (`auth.admin`) : `POST/DELETE /v1/admin/principals/{id}/roles/{role}` (le retrait révoque les jetons ;
auto-retrait d'`auth.admin` refusé), `POST /v1/admin/principals/{id}/disable|enable|revoke-tokens`, `GET /v1/admin/sessions`,
`GET /v1/admin/audit`.

---

## 5. Assistant opérateur (agent RAG — contrat consommateur)

L'agent documentaire est livré par un autre lot ; le frontend s'appuie sur le contrat ci-dessous, à confirmer par ce lot. La passerelle applique l'authentification (`auth_request`, rôle `noc.viewer`) et transmet `X-Auth-Sub` / `X-Auth-Roles`.

`POST /api/assistant/v1/chat`

```json
{
  "conversation_id": null,
  "message": "Pourquoi payment-api est-il passé en SYNTHETIC_ONLY ?",
  "context": { "incident_id": "c7d1b3f4-…", "phase": "RECOVERING" }
}
```

`200`

```json
{
  "conversation_id": "conv_01J…",
  "message_id": "msg_01J…",
  "answer": "Le playbook PB-INTEGRITY-RESTORE place la plateforme en quarantaine synthétique…",
  "sources": [
    { "title": "Runbook — Intégrité des soldes", "uri": "kb://runbooks/integrity-restore", "excerpt": "…", "score": 0.91 }
  ],
  "created_at": "2026-10-19T08:16:20Z"
}
```

Optionnel : `Accept: text/event-stream` ⇒ événements `token` (`{"delta": "…"}`), `sources`, `done`. Délai maximal côté passerelle : 60 s.

**Comportement de la passerelle (implémenté, Lot 5)** — engagements envers le lot RAG :

| Situation | Réponse au navigateur |
|---|---|
| Pas de jeton / jeton invalide | `401 UNAUTHENTICATED` (problem+json), l'agent n'est pas appelé |
| Rôle `noc.viewer` absent | `403 FORBIDDEN`, l'agent n'est pas appelé |
| Agent injoignable, en erreur 502/503/504 ou hors délai | `503 ASSISTANT_UNAVAILABLE` — affiché comme indisponibilité de l'assistant, sans impact sur le reste de la console |
| Plus de 20 requêtes/min par client (rafale 10) | `429` |

En-têtes reçus par l'agent : `X-Auth-Sub`, `X-Auth-Roles`, `X-Request-ID`, `X-Forwarded-For`. Les en-têtes `Authorization` et `Cookie` du navigateur sont **retirés** : l'agent ne reçoit jamais le jeton de l'utilisateur. Corps limité à 64 Kio. Amont configuré par `ASSISTANT_UPSTREAM_URL` (défaut `http://rag-agent:8000`, réseau `app`).
