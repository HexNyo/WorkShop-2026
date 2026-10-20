"""Métriques spécifiques à l'auth-service."""

from prometheus_client import Counter

LOGINS = Counter("ra_auth_logins_total", "Tentatives de connexion humaines", ["outcome"])
TOKENS_ISSUED = Counter("ra_auth_tokens_issued_total", "Jetons d'accès émis", ["grant"])
