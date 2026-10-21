#!/bin/sh
# Certificat autosigné pour l'accès https depuis le réseau local (la caméra exige un contexte sécurisé hors localhost).
# Conservé dans le volume frontend-tls ; regénéré seulement si TLS_SAN change.
set -eu

dir=/etc/nginx/tls
san="${TLS_SAN:-DNS:localhost,IP:127.0.0.1}"
if [ ! -s "$dir/cert.pem" ] || [ "$(cat "$dir/san.txt" 2>/dev/null)" != "$san" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 -subj "/CN=Workshop 2026" \
    -addext "subjectAltName=$san" -keyout "$dir/key.pem" -out "$dir/cert.pem" 2>/dev/null
  echo "$san" > "$dir/san.txt"
  echo "15-tls-cert: certificat autosigné généré pour $san"
fi
