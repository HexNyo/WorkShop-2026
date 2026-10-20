#!/bin/sh
# Génère (ou non) la route du laboratoire de pannes selon CHAOS_LAB_ENABLED.
# Exécuté par l'entrypoint nginx après le rendu des templates.
set -eu

mkdir -p /etc/nginx/lab
if [ "${CHAOS_LAB_ENABLED:-false}" = "true" ]; then
  cat > /etc/nginx/lab/lab.conf <<'EOF'
location /api/payment/lab/v1/ {
    rewrite ^/api/payment/(lab/v1/.*)$ /$1 break;
    proxy_pass $payment_upstream;
    include /etc/nginx/snippets/proxy.conf;
}
EOF
  echo "40-lab-routes: CHAOS LAB route ENABLED (never in production)"
else
  : > /etc/nginx/lab/lab.conf
  echo "40-lab-routes: chaos lab route disabled"
fi
