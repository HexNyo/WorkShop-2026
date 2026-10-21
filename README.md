# PROJECT RESILIENCE-ALPHA — Plateforme de paiement résiliente & Zero-Touch Recovery

Plateforme de paiement **100 % fictive** en microservices, avec un moteur de remédiation autonome qui détecte, corrige et **prouve** le rétablissement du service par une transaction synthétique de bout en bout, avant de clore un incident.

| Composant | Rôle | Lot |
|---|---|---|
| `database` | MariaDB >= 10.6 externe — bases `ra_auth`, `ra_payment`, `ra_remediation`, invariants financiers en base | 1 (schéma) · 2 (image) |
| `auth-service` | JWT RS256, RBAC, M2M, révocation | 2 |
| `payment-api` | Transactions ACID idempotentes, santé avancée, administration de remédiation | 3 |
| `remediation-engine` | Webhook d'alertes, machine à états, playbooks, vérification synthétique, watchdog, flux SSE | 4 |
| `rag-agent` + `ollama` | Assistant documentaire gratuit et local : recherche dans `docs/` et le catalogue de playbooks, réponse générée par `qwen2.5:7b` via Ollama (GPU NVIDIA ; modèle de ~4,7 Go téléchargé au premier `up`) | 6 |
| `frontend-dashboard` | React + TypeScript + Tailwind (portail métier, console NOC/SOC, assistant RAG) et passerelle nginx | 5 |

## Documentation

1. [Architecture applicative](docs/01-architecture.md) — composants, arborescence, réseaux, sécurité, RBAC, observabilité
2. [Modèle de données](docs/02-modele-donnees.md) — MCD/MPD, invariants, intégrité et réparation
3. [Contrats d'interface](docs/03-contrats-api.md) — endpoints, payloads, erreurs, flux SSE, passerelle
4. [Boucle de remédiation](docs/04-boucle-remediation.md) — diagramme de séquence, machine à états, protocole STM, watchdog

Contrats inter-lots : [alert-webhook.schema.json](contracts/alert-webhook.schema.json) (lot Détection) · [sse-events.schema.json](contracts/sse-events.schema.json) (console) · § 5 de [docs/03](docs/03-contrats-api.md) (lot RAG).

## Démarrage rapide

Prérequis : Docker (Compose v2), Bash avec `openssl` (Git Bash sous Windows) et une instance MariaDB >= 10.6
joignable depuis l'hôte Docker (`DB_HOST`, `DB_PORT` dans `.env`).

```bash
./scripts/generate-dev-secrets.sh          # crée .env : clé RSA 3072 + secrets aléatoires (jamais versionné)
MARIADB_ADMIN_PASSWORD=... docker compose --profile init run --rm db-init   # une seule fois : bases ra_*, comptes, démo
docker compose up -d --build --wait        # conteneurs non-root et en lecture seule
```

Ouvrir **http://localhost:8088** (seul port publié, lié à `127.0.0.1` ; `FRONTEND_PUBLIC_PORT` pour le changer).

| Identifiant | Rôles | Vue d'arrivée |
|---|---|---|
| `alice`, `bob`, `merchant` | `payment.customer` | Portail métier |
| `noc-operator` | `noc.viewer`, `payment.operator` | Console NOC/SOC, assistant |
| `admin` | `auth.admin`, `remediation.admin`, `noc.viewer`, `payment.operator`, `chaos.operator` | Console + laboratoire d'attaque |

Les mots de passe sont ceux générés dans `.env` (`AUTH_BOOTSTRAP_<IDENTIFIANT>_SECRET`, ex. `AUTH_BOOTSTRAP_NOC_OPERATOR_SECRET`).

## Démonstration de la reprise autonome

Prérequis : `CHAOS_LAB_ENABLED=true` dans `.env` **avant** la première initialisation de la base.

1. **Avant** — connecté en `admin`, la console affiche la phase *Nominal* et la santé des services.
2. **Pendant** — *Laboratoire d'attaque › Altérer un solde* : l'interface n'envoie aucune alerte. La transaction synthétique planifiée détecte l'atteinte à l'intégrité (≤ 60 s), le moteur ouvre l'incident, place la plateforme en quarantaine synthétique et répare les soldes depuis le grand livre. Chaque étape apparaît en direct.
3. **Après** — les 9 contrôles de la vérification post-reprise passent, le trafic réel est rouvert, l'incident est clos et la phase devient *Rétabli et vérifié*.

Alternatives : alerte d'un détecteur externe simulé (`docker compose --profile tools run --rm detector-simulator --category DATA_INTEGRITY_VIOLATION --service payment-api`) ; pilotage en ligne de commande (`docker compose exec remediation-engine ra-ctl --user admin incidents`).

## Tests

| Suite | Commande | Contenu |
|---|---|---|
| Base de données | `./scripts/test-database.sh` | 48 assertions sur MariaDB éphémère : authentification, invariants financiers, privilèges, attaque simulée et réparation, garde de clôture d'incident |
| auth-service — unitaires | `docker build --target test -f services/auth-service/Dockerfile .` | 29 tests (jetons, clés, politiques, Argon2, ra_common) |
| auth-service — bout en bout | `docker compose --profile test run --rm --build auth-tests` | 15 scénarios : login, verrouillage, rotation et réutilisation du refresh, M2M, confinement, introspection, vérification côté resource server |
| payment-api — unitaires | `docker build --target test -f services/payment-api/Dockerfile .` | 28 tests (montants, modes d'écriture, visibilité, quotas, tickets et diffusion SSE) |
| payment-api — bout en bout | `docker compose --profile test run --rm --build payment-tests` | 22 scénarios : cycle de vie, idempotence, double dépense concurrente, quarantaine, gel, quotas, révocation, SSE, altération → réparation, pannes injectées |
| remediation-engine — unitaires | `docker build --target test -f services/remediation-engine/Dockerfile .` | 17 tests (HMAC, empreinte, transitions, phases, playbooks, Docker, STM V1→V9 simulée) |
| remediation-engine — bout en bout | `docker compose --profile test run --rm --build remediation-tests` | 12 scénarios : isolation des listeners, webhook JWT + HMAC, RBAC/SSE, suppression, intégrité, redémarrage, identifiants, escalade, watchdog sans alerte externe |
| frontend — unitaires | `docker build --target test frontend-dashboard` | `tsc` strict + 18 tests Vitest (client HTTP, sémantique des états, géométrie de la frise, composants) |
| passerelle | `docker compose --profile test run --rm gateway-tests` | 28 tests depuis le réseau `edge` : isolation réseau, en-têtes de sécurité, liste blanche, SSE sans tampon, assistant protégé, limitation du login |
| interface | `docker compose --profile test run --rm ui-tests` | 5 scénarios Playwright (Chromium) dont la boucle complète attaque → détection → remédiation → vérification → rétabli ; captures dans `frontend-dashboard/e2e/artifacts/screenshots/` |

`make test` enchaîne toutes les suites.

## Règles du dépôt

* Aucun secret dans le dépôt : toute valeur sensible passe par l'environnement (cf. [.env.example](.env.example)).
* Données exclusivement fictives (comptes `RA-NNNN-NNNN`, aucun IBAN ni numéro de carte).
* Le laboratoire d'injection de pannes (`CHAOS_LAB_ENABLED`) est désactivé par défaut et ne doit jamais l'être en production.
