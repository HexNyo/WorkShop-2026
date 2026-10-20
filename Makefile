# PROJECT RESILIENCE-ALPHA — raccourcis de développement
# (sous Windows : exécuter depuis Git Bash, ou lancer directement les commandes.)

COMPOSE ?= docker compose

.PHONY: help secrets build up down reset logs ps test test-db test-auth-unit test-auth-e2e test-payment-unit test-payment-e2e test-remediation-unit test-remediation-e2e test-rag-unit test-frontend-unit test-gateway test-ui simulate-alert

help:
	@echo "secrets        génère .env (secrets aléatoires, clé RSA)"
	@echo "up / down      démarre / arrête la plateforme"
	@echo "reset          arrête et SUPPRIME les données (volume PostgreSQL)"
	@echo "test           exécute toutes les suites (base, unitaires, e2e)"

secrets:
	./scripts/generate-dev-secrets.sh

build:
	$(COMPOSE) build

up:
	$(COMPOSE) up -d --build --wait

down:
	$(COMPOSE) down

reset:
	$(COMPOSE) down --volumes

logs:
	$(COMPOSE) logs -f --tail=100

ps:
	$(COMPOSE) ps

test: test-db test-auth-unit test-payment-unit test-remediation-unit test-rag-unit test-frontend-unit test-auth-e2e test-payment-e2e test-remediation-e2e test-gateway test-ui

test-db:
	./scripts/test-database.sh

test-auth-unit:
	docker build --target test -f services/auth-service/Dockerfile -t resilience-alpha/auth-service:test .

test-auth-e2e: up
	$(COMPOSE) --profile test run --rm --build auth-tests

test-payment-unit:
	docker build --target test -f services/payment-api/Dockerfile -t resilience-alpha/payment-api:test .

test-payment-e2e: up
	$(COMPOSE) --profile test run --rm --build payment-tests

test-remediation-unit:
	docker build --target test -f services/remediation-engine/Dockerfile -t resilience-alpha/remediation-engine:test .

test-rag-unit:
	docker build --target test -f services/rag-agent/Dockerfile -t resilience-alpha/rag-agent:test .

test-remediation-e2e: up
	$(COMPOSE) --profile test run --rm --build remediation-tests

# usage : make simulate-alert CATEGORY=SERVICE_UNAVAILABLE SERVICE=payment-api
CATEGORY ?= DATA_INTEGRITY_VIOLATION
SERVICE ?= payment-api
simulate-alert:
	$(COMPOSE) --profile tools run --rm detector-simulator --category $(CATEGORY) --service $(SERVICE)

test-frontend-unit:
	docker build --target test -t resilience-alpha/frontend-dashboard:test frontend-dashboard

test-gateway: up
	$(COMPOSE) --profile test run --rm gateway-tests

test-ui: up
	$(COMPOSE) --profile test run --rm ui-tests
