"""Authentification machine-à-machine (OAuth2 client_credentials, RFC 6749 § 4.4)."""

from __future__ import annotations

import logging

from app.core.db import Database
from app.core.passwords import SecretHasher
from app.domain.errors import OAuthError
from app.domain.models import IssuedAccessToken, PrincipalKind
from app.domain.policies import service_audiences, service_roles_for
from app.observability import TOKENS_ISSUED
from app.repositories.audit import AuditRepository
from app.repositories.principals import PrincipalRepository
from app.services.tokens import TokenService
from ra_common.logging import log_event

logger = logging.getLogger("auth.client_credentials")


class ClientCredentialsService:
    """Pas de verrouillage sur échec pour les comptes de service : un attaquant ne
    doit pas pouvoir neutraliser la remédiation par déni de service. Les secrets de
    service sont longs et aléatoires (≥ 16 caractères, 48 en génération standard)."""

    def __init__(
        self,
        *,
        db: Database,
        hasher: SecretHasher,
        tokens: TokenService,
        principals: PrincipalRepository,
        audit: AuditRepository,
    ) -> None:
        self._db = db
        self._hasher = hasher
        self._tokens = tokens
        self._principals = principals
        self._audit = audit

    async def issue(
        self, *, client_id: str, client_secret: str, audience: str | None, client_ip: str | None
    ) -> IssuedAccessToken:
        async with self._db.connection() as conn:
            principal = await self._principals.get_by_username(conn, client_id.strip().lower())

        eligible = (
            principal is not None
            and principal.kind is PrincipalKind.SERVICE
            and principal.is_active
            and principal.has_secret
        )
        valid = await self._hasher.verify(principal.secret_hash if eligible else None, client_secret)
        if not eligible or not valid:
            async with self._db.transaction() as conn:
                await self._audit.record(
                    conn,
                    event_type="CLIENT_CREDENTIALS_FAILURE",
                    outcome="FAILURE",
                    principal_id=principal.id if principal else None,
                    client_ip=client_ip,
                    details={"client_id": client_id[:64]},
                )
            log_event(logger, logging.WARNING, "auth.client_auth_failed", "client authentication failed", client_id=client_id[:64])
            raise OAuthError("invalid_client", "client authentication failed", status=401)

        allowed = service_audiences(principal.roles)
        if not allowed:
            raise OAuthError("unauthorized_client", "this client is not allowed to obtain access tokens")
        if audience is not None and audience not in allowed:
            raise OAuthError("invalid_target", f"audience '{audience}' is not allowed for this client")
        audiences = (audience,) if audience else tuple(sorted(allowed))
        issued = self._tokens.issue(principal, audiences=audiences, roles=service_roles_for(principal.roles, audiences))
        TOKENS_ISSUED.labels(grant="client_credentials").inc()
        return issued
