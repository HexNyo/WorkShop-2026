"""Authentification des humains : connexion, rotation du refresh, déconnexion."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from app.core.config import Settings
from app.core.db import Database
from app.core.passwords import SecretHasher, generate_refresh_token, hash_refresh_token
from app.domain.errors import AccountLocked, InvalidCredentials, PrincipalNotFound, RefreshTokenInvalid, RefreshTokenReused
from app.domain.models import LoginResult, Principal, PrincipalKind
from app.domain.policies import USER_AUDIENCES
from app.observability import LOGINS, TOKENS_ISSUED
from app.repositories.audit import AuditRepository
from app.repositories.principals import PrincipalRepository
from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.revocations import RevocationRepository
from app.services.tokens import TokenService
from ra_common.logging import log_event
from ra_common.security.tokens import AccessTokenClaims

logger = logging.getLogger("auth.authentication")


class AuthenticationService:
    def __init__(
        self,
        *,
        settings: Settings,
        db: Database,
        hasher: SecretHasher,
        tokens: TokenService,
        principals: PrincipalRepository,
        refresh_tokens: RefreshTokenRepository,
        revocations: RevocationRepository,
        audit: AuditRepository,
    ) -> None:
        self._settings = settings
        self._db = db
        self._hasher = hasher
        self._tokens = tokens
        self._principals = principals
        self._refresh = refresh_tokens
        self._revocations = revocations
        self._audit = audit

    # ------------------------------------------------------------------ login
    async def login(self, username: str, password: str, *, client_ip: str | None, user_agent: str | None) -> LoginResult:
        normalized = username.strip().lower()
        async with self._db.connection() as conn:
            principal = await self._principals.get_by_username(conn, normalized)

        now = datetime.now(UTC)
        eligible = (
            principal is not None
            and principal.kind is PrincipalKind.USER
            and principal.is_active
            and principal.has_secret
        )
        if eligible and principal.is_locked(now):
            await self._audit_failure("ACCOUNT_LOCKED", principal.id, client_ip, normalized, "locked")
            LOGINS.labels(outcome="locked").inc()
            raise AccountLocked(int((principal.locked_until - now).total_seconds()))

        # Vérification Argon2 systématique (empreinte factice si inéligible) : temps constant.
        valid = await self._hasher.verify(principal.secret_hash if eligible else None, password)
        if not eligible or not valid:
            await self._register_failure(principal if eligible else None, normalized, client_ip)
            raise InvalidCredentials()

        new_hash = await self._hasher.hash(password) if self._hasher.needs_rehash(principal.secret_hash) else None
        refresh_plain = generate_refresh_token()
        refresh_expires = now + timedelta(seconds=self._settings.refresh_token_ttl_seconds)
        access = self._tokens.issue(principal, audiences=USER_AUDIENCES, roles=principal.roles)

        async with self._db.transaction() as conn:
            await self._principals.record_login_success(conn, principal.id, new_hash)
            await self._refresh.create(
                conn,
                family_id=uuid4(),
                principal_id=principal.id,
                token_hash=hash_refresh_token(refresh_plain),
                expires_at=refresh_expires,
                client_ip=client_ip,
                user_agent=user_agent,
            )
            await self._audit.record(
                conn,
                event_type="LOGIN_SUCCESS",
                outcome="SUCCESS",
                principal_id=principal.id,
                client_ip=client_ip,
                details={"jti": str(access.jti)},
            )
        LOGINS.labels(outcome="success").inc()
        TOKENS_ISSUED.labels(grant="password").inc()
        log_event(logger, logging.INFO, "auth.login_succeeded", "login succeeded", principal_id=str(principal.id))
        return LoginResult(access=access, refresh_token=refresh_plain, refresh_expires_at=refresh_expires, principal=principal)

    async def _register_failure(self, principal: Principal | None, username: str, client_ip: str | None) -> None:
        locked_until = None
        async with self._db.transaction() as conn:
            if principal is not None:
                locked_until = await self._principals.record_login_failure(
                    conn,
                    principal.id,
                    max_failures=self._settings.max_failed_logins,
                    lockout_seconds=self._settings.lockout_seconds,
                )
            await self._audit.record(
                conn,
                event_type="LOGIN_FAILURE",
                outcome="FAILURE",
                principal_id=principal.id if principal else None,
                client_ip=client_ip,
                details={"username": username[:64], "account_locked": locked_until is not None},
            )
        LOGINS.labels(outcome="failure").inc()
        log_event(
            logger,
            logging.WARNING,
            "auth.login_failed",
            "login failed",
            username=username[:64],
            account_locked=locked_until is not None,
        )

    async def _audit_failure(
        self, event_type: str, principal_id: UUID | None, client_ip: str | None, username: str, reason: str
    ) -> None:
        async with self._db.transaction() as conn:
            await self._audit.record(
                conn,
                event_type=event_type,
                outcome="DENIED",
                principal_id=principal_id,
                client_ip=client_ip,
                details={"username": username[:64], "reason": reason},
            )

    # ---------------------------------------------------------------- refresh
    async def refresh(self, refresh_plain: str, *, client_ip: str | None, user_agent: str | None) -> LoginResult:
        token_hash = hash_refresh_token(refresh_plain)
        reused_family: UUID | None = None
        reused_principal: UUID | None = None

        async with self._db.transaction() as conn:
            consumed = await self._refresh.consume(conn, token_hash)
            if consumed is None:
                existing = await self._refresh.find(conn, token_hash)
                if existing is not None and existing.used_at is not None and existing.revoked_at is None:
                    # Réutilisation d'un jeton déjà échangé : vol probable => toute la famille tombe.
                    await self._refresh.revoke_family(conn, existing.family_id, "REUSE_DETECTED")
                    await self._audit.record(
                        conn,
                        event_type="REFRESH_TOKEN_REUSE",
                        outcome="DENIED",
                        principal_id=existing.principal_id,
                        client_ip=client_ip,
                        details={"family_id": str(existing.family_id)},
                    )
                    reused_family, reused_principal = existing.family_id, existing.principal_id
                else:
                    raise RefreshTokenInvalid()
            else:
                principal = await self._principals.get_by_id(conn, consumed.principal_id)
                if (
                    principal is None
                    or principal.kind is not PrincipalKind.USER
                    or not principal.is_active
                    or consumed.issued_at < principal.tokens_valid_after
                ):
                    await self._refresh.revoke_family(conn, consumed.family_id, "PRINCIPAL_INVALID")
                    invalid = True
                else:
                    invalid = False
                    refresh_new = generate_refresh_token()
                    await self._refresh.create(
                        conn,
                        family_id=consumed.family_id,
                        principal_id=principal.id,
                        token_hash=hash_refresh_token(refresh_new),
                        expires_at=consumed.expires_at,  # durée de vie absolue par famille
                        client_ip=client_ip,
                        user_agent=user_agent,
                    )
                    access = self._tokens.issue(principal, audiences=USER_AUDIENCES, roles=principal.roles)
                    await self._audit.record(
                        conn,
                        event_type="TOKEN_REFRESHED",
                        outcome="SUCCESS",
                        principal_id=principal.id,
                        client_ip=client_ip,
                        details={"family_id": str(consumed.family_id), "jti": str(access.jti)},
                    )

        if reused_family is not None:
            log_event(
                logger,
                logging.WARNING,
                "auth.refresh_token_reuse",
                "refresh token reuse detected, family revoked",
                principal_id=str(reused_principal),
                family_id=str(reused_family),
            )
            raise RefreshTokenReused()
        if invalid:
            raise RefreshTokenInvalid()
        TOKENS_ISSUED.labels(grant="refresh_token").inc()
        return LoginResult(access=access, refresh_token=refresh_new, refresh_expires_at=consumed.expires_at, principal=principal)

    # ----------------------------------------------------------------- logout
    async def logout(self, claims: AccessTokenClaims, refresh_plain: str | None, *, client_ip: str | None) -> None:
        async with self._db.transaction() as conn:
            await self._revocations.revoke_jti(
                conn,
                jti=UUID(claims.jti),
                principal_id=UUID(claims.sub),
                expires_at=datetime.fromtimestamp(claims.exp, UTC),
                reason="LOGOUT",
            )
            if refresh_plain:
                existing = await self._refresh.find(conn, hash_refresh_token(refresh_plain))
                if existing is not None and str(existing.principal_id) == claims.sub:
                    await self._refresh.revoke_family(conn, existing.family_id, "LOGOUT")
            await self._audit.record(
                conn, event_type="LOGOUT", outcome="SUCCESS", principal_id=UUID(claims.sub), client_ip=client_ip
            )

    # --------------------------------------------------------------------- me
    async def me(self, claims: AccessTokenClaims) -> Principal:
        async with self._db.connection() as conn:
            principal = await self._principals.get_by_id(conn, UUID(claims.sub))
        if principal is None:
            raise PrincipalNotFound()
        return principal
