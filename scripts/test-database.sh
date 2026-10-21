#!/usr/bin/env bash
# =============================================================================
# PROJECT RESILIENCE-ALPHA — tests d'acceptation de la base sur instance éphémère
# Construit database/Dockerfile (MariaDB + scripts d'init), démarre une base jetable
# (mots de passe aléatoires, laboratoire activé), exécute la suite puis détruit tout.
# Ne touche jamais l'instance MariaDB externe.
# =============================================================================
set -euo pipefail
# Git Bash (Windows) : empêche la réécriture des chemins conteneur (/tests/…).
export MSYS_NO_PATHCONV=1

# `pwd -W` donne un chemin Windows natif sous Git Bash ; repli sur `pwd` ailleurs.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && (pwd -W 2>/dev/null || pwd))"
IMAGE="resilience-alpha/database:test"
NAME="ra-db-test-$$"

rand() { openssl rand -hex 24; }

cleanup() { docker rm -f "$NAME" >/dev/null 2>&1 || true; }
trap cleanup EXIT

docker build --quiet -t "$IMAGE" "$ROOT/database" >/dev/null

docker run -d --name "$NAME" \
  -e MARIADB_ROOT_PASSWORD="$(rand)" \
  -e RA_DB_AUTH_PASSWORD="$(rand)" \
  -e RA_DB_PAYMENT_PASSWORD="$(rand)" \
  -e RA_DB_PAYMENT_MAINT_PASSWORD="$(rand)" \
  -e RA_DB_REMEDIATION_PASSWORD="$(rand)" \
  -e CHAOS_LAB_ENABLED=true \
  "$IMAGE" >/dev/null

# L'initialisation démarre un serveur temporaire (socket seulement) puis le
# serveur définitif : on attend que ce dernier écoute en TCP.
for _ in $(seq 1 90); do
  if docker exec "$NAME" healthcheck.sh --connect 2>/dev/null; then break; fi
  if ! docker ps --quiet --filter "name=$NAME" | grep -q .; then
    docker logs "$NAME" >&2; echo "FATAL: la base n'a pas démarré" >&2; exit 1
  fi
  sleep 1
done

docker exec "$NAME" bash /tests/test_invariants.sh
