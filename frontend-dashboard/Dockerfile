# syntax=docker/dockerfile:1.7
# =============================================================================
# PROJECT RESILIENCE-ALPHA — frontend-dashboard (SPA + passerelle)
#   deps    : dépendances npm figées (package-lock.json)
#   test    : contrôle de types + tests unitaires (exécutés au build)
#   build   : bundle de production (ne se construit que si les tests passent)
#   runtime : nginx non-root, configuration en liste blanche, aucun outil de build
# =============================================================================
ARG NODE_IMAGE=node:22.12.0-alpine3.20
ARG NGINX_IMAGE=nginxinc/nginx-unprivileged:1.27.3-alpine

FROM ${NODE_IMAGE} AS deps
WORKDIR /app
ENV CI=true NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false NPM_CONFIG_AUDIT=false
COPY package.json package-lock.json ./
RUN npm ci

FROM deps AS test
COPY . .
RUN npm run typecheck && npx vitest run

FROM test AS build
RUN npm run build

FROM ${NGINX_IMAGE} AS runtime
LABEL org.opencontainers.image.title="resilience-alpha-frontend-dashboard" \
      org.opencontainers.image.description="Portail métier, console NOC/SOC et assistant — passerelle publique" \
      org.opencontainers.image.version="1.0.0"
ENV NGINX_ENTRYPOINT_QUIET_LOGS=1 \
    AUTH_UPSTREAM=auth-service:8000 \
    PAYMENT_UPSTREAM=payment-api:8000 \
    SUPERVISION_UPSTREAM=remediation-engine:8002 \
    ASSISTANT_UPSTREAM_URL=http://rag-agent:8000 \
    CHAOS_LAB_ENABLED=false
COPY nginx/default.conf.template /etc/nginx/templates/default.conf.template
COPY nginx/snippets/ /etc/nginx/snippets/
COPY --chmod=0755 nginx/40-lab-routes.sh /docker-entrypoint.d/40-lab-routes.sh
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 8080
HEALTHCHECK --interval=10s --timeout=3s --start-period=10s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
