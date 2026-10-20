#!/usr/bin/env bash
# =============================================================================
# PROJECT RESILIENCE-ALPHA — génération des secrets d'un environnement de dev
# -----------------------------------------------------------------------------
# Produit `.env` à partir de `.env.example` en remplissant chaque variable VIDE :
#   *_PASSWORD, *_SECRET            -> 48 caractères hexadécimaux aléatoires
#   AUTH_JWT_PRIVATE_KEY_PEM_B64    -> clé RSA 3072 bits (PEM PKCS#8, base64)
# Les valeurs non vides de .env.example sont reprises telles quelles.
#
# Usage :
#   scripts/generate-dev-secrets.sh            crée .env (refuse s'il existe)
#   scripts/generate-dev-secrets.sh --update   conserve les valeurs de .env et
#                                              ajoute les variables apparues depuis
#   scripts/generate-dev-secrets.sh --force    régénère tout (anciens secrets perdus)
# Aucun secret n'est affiché.
# =============================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TEMPLATE="$ROOT/.env.example"
TARGET="$ROOT/.env"
MODE="${1:-create}"

case "$MODE" in
  create)
    if [ -e "$TARGET" ]; then
      echo "ERREUR: $TARGET existe déjà. --update pour compléter, --force pour tout régénérer." >&2
      exit 1
    fi ;;
  --update|--force) ;;
  *) echo "usage: $0 [--update|--force]" >&2; exit 2 ;;
esac
command -v openssl >/dev/null || { echo "ERREUR: openssl est requis" >&2; exit 1; }

declare -A existing=()
if [ "$MODE" = "--update" ] && [ -e "$TARGET" ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    if [[ "$line" =~ ^([A-Z0-9_]+)=(.*)$ ]]; then
      existing["${BASH_REMATCH[1]}"]="${BASH_REMATCH[2]}"
    fi
  done <"$TARGET"
fi

umask 077
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT

random_secret() { openssl rand -hex 24; }
rsa_private_key_b64() {
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:3072 2>/dev/null | base64 | tr -d '\r\n'
}

added=0
render() {
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    if [[ "$line" =~ ^([A-Z0-9_]+)=(.*)$ ]]; then
      key="${BASH_REMATCH[1]}"
      if [ -n "${existing[$key]+set}" ]; then
        printf '%s=%s\n' "$key" "${existing[$key]}"
        continue
      fi
      if [ -z "${BASH_REMATCH[2]}" ]; then
        case "$key" in
          AUTH_JWT_PRIVATE_KEY_PEM_B64) printf '%s=%s\n' "$key" "$(rsa_private_key_b64)"; continue ;;
          *_PASSWORD|*_SECRET)          printf '%s=%s\n' "$key" "$(random_secret)"; continue ;;
        esac
      fi
    fi
    printf '%s\n' "$line"
  done <"$TEMPLATE"
}

render >"$tmp"
for key in $(grep -oE '^[A-Z0-9_]+' "$tmp"); do
  [ -n "${existing[$key]+set}" ] || added=$((added + 1))
done
cp "$tmp" "$TARGET"
chmod 600 "$TARGET" 2>/dev/null || true
if [ "$MODE" = "--update" ]; then
  echo "OK: $TARGET complété ($added variable(s) ajoutée(s), valeurs existantes conservées)."
else
  echo "OK: $TARGET créé. Ne jamais le versionner."
fi
