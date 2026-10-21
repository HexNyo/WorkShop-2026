"""Administration et confinement des principaux, révocation des jetons, flux de révocation."""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from uuid import UUID

import asyncpg
from ra_common.db import sqlstate

from app.core.config import Settings
from app.core.db import Database
from app.core.passwords import SecretHasher
from app.domain.errors import AccountLocked, InvalidState, PolicyViolation, PrincipalNotFound
from app.domain.models import ContainmentResult, Principal, PrincipalKind, RevocationEntry
from app.domain.policies import ROLE_AUTH_ADMIN, check_containment_allowed
from app.repositories.audit import AuditRepository
from app.repositories.principals import PrincipalRepository
from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.revocations import RevocationRepository
from ra_common.logging import log_event
from ra_common.security.tokens import AccessTokenClaims

logger = logging.getLogger("auth.principals")


class PrincipalService:
    def __init__(
        self,
        *,
        settings: Settings,
        db: Database,
        hasher: SecretHasher,
        principals: PrincipalRepository,
        refresh_tokens: RefreshTokenRepository,
        revocations: RevocationRepository,
        audit: AuditRepository,
    ) -> None:
        self._settings = settings
        self._db = db
        self._hasher = hasher
        self._principals = principals
        self._refresh = refresh_tokens
        self._revocations = revocations
        self._audit = audit

    @property
    def _revocation_horizon(self) -> timedelta:
        return timedelta(seconds=self._settings.access_token_ttl_seconds + self._settings.clock_leeway_seconds)

    # ------------------------------------------------------------ révocation
    async def revoke_token(self, actor: AccessTokenClaims, jti: UUID | None, reason: str) -> None:
        own = jti is None or str(jti) == actor.jti
        if not own and ROLE_AUTH_ADMIN not in actor.roles:
            raise PolicyViolation("only auth.admin may revoke another token")
        target_jti = UUID(actor.jti) if own else jti
        expires_at = (
            datetime.fromtimestamp(actor.exp, UTC) if own else datetime.now(UTC) + self._revocation_horizon
        )
        async with self._db.transaction() as conn:
            await self._revocations.revoke_jti(
                conn,
                jti=target_jti,
                principal_id=UUID(actor.sub) if own else None,
                expires_at=expires_at,
                reason=reason,
            )
            await self._audit.record(
                conn,
                event_type="TOKEN_REVOKED",
                outcome="SUCCESS",
                principal_id=UUID(actor.sub) if own else None,
                actor_principal_id=actor.sub,
                details={"jti": str(target_jti), "reason": reason},
            )

    async def revocation_feed(self, *, since: int, limit: int) -> tuple[int, list[RevocationEntry]]:
        async with self._db.connection() as conn:
            items = await self._revocations.list_since(conn, since=since, limit=limit)
            cursor = items[-1].seq if items else max(since, 0)
            if not items and since == 0:
                cursor = await self._revocations.max_seq(conn)
        return cursor, items

    # ------------------------------------------------------------- confinement
    async def contain(
        self,
        actor: AccessTokenClaims,
        principal_id: UUID,
        *,
        disable: bool,
        reason: str,
        incident_id: UUID | None,
    ) -> ContainmentResult:
        async with self._db.transaction() as conn:
            if not await self._principals.lock(conn, principal_id):
                raise PrincipalNotFound()
            target = await self._principals.get_by_id(conn, principal_id)
            check_containment_allowed(actor_sub=actor.sub, actor_roles=actor.roles, target=target, disable=disable)

            not_before = await self._principals.bump_tokens_valid_after(conn, principal_id)
            if disable:
                await self._principals.set_active(conn, principal_id, False)
            await self._revocations.revoke_principal(
                conn,
                principal_id=principal_id,
                not_before=not_before,
                expires_at=not_before + self._revocation_horizon,
                reason=reason,
            )
            revoked = await self._refresh.revoke_all_for_principal(conn, principal_id, reason)
            event = "PRINCIPAL_DISABLED" if disable else "PRINCIPAL_TOKENS_REVOKED"
            await self._audit.record(
                conn,
                event_type=event,
                outcome="SUCCESS",
                principal_id=principal_id,
                actor_principal_id=actor.sub,
                details={
                    "reason": reason,
                    "incident_id": str(incident_id) if incident_id else None,
                    "refresh_tokens_revoked": revoked,
                },
            )
        log_event(
            logger,
            logging.WARNING,
            "auth.principal_contained",
            "principal contained",
            target_principal_id=str(principal_id),
            disable=disable,
            reason=reason,
            incident_id=str(incident_id) if incident_id else None,
        )
        return ContainmentResult(
            principal_id=principal_id,
            is_active=target.is_active and not disable,
            tokens_valid_after=not_before,
            refresh_tokens_revoked=revoked,
        )

    async def enable(self, actor: AccessTokenClaims, principal_id: UUID, *, reason: str) -> Principal:
        async with self._db.transaction() as conn:
            if not await self._principals.lock(conn, principal_id):
                raise PrincipalNotFound()
            target = await self._principals.get_by_id(conn, principal_id)
            if not target.has_secret:
                raise InvalidState("principal has no secret yet: provide its bootstrap secret first")
            await self._principals.set_active(conn, principal_id, True)
            await self._audit.record(
                conn,
                event_type="PRINCIPAL_ENABLED",
                outcome="SUCCESS",
                principal_id=principal_id,
                actor_principal_id=actor.sub,
                details={"reason": reason},
            )
            refreshed = await self._principals.get_by_id(conn, principal_id)
        log_event(logger, logging.INFO, "auth.principal_enabled", "principal enabled", target_principal_id=str(principal_id))
        return refreshed

    async def list_page(self, *, after_username: str | None, limit: int) -> tuple[list[Principal], str | None]:
        async with self._db.connection() as conn:
            rows = await self._principals.list_page(conn, after_username=after_username, limit=limit + 1)
        next_cursor = rows[limit - 1].username if len(rows) > limit else None
        return rows[:limit], next_cursor

    # -------------------------------------------------------------- rôles (RBAC)
    async def set_role(self, actor: AccessTokenClaims, principal_id: UUID, role: str, *, grant: bool) -> Principal:
        if not grant and role == ROLE_AUTH_ADMIN and str(principal_id) == actor.sub:
            raise PolicyViolation("an administrator cannot remove their own auth.admin role")
        async with self._db.transaction() as conn:
            if not await self._principals.lock(conn, principal_id):
                raise PrincipalNotFound()
            try:
                async with conn.transaction():
                    if grant:
                        await self._principals.grant_role(conn, principal_id, role, UUID(actor.sub))
                    else:
                        await self._principals.revoke_role(conn, principal_id, role)
            except asyncpg.ForeignKeyViolationError as exc:
                raise InvalidState(f"unknown role {role}") from exc
            except asyncpg.PostgresError as exc:
                if sqlstate(exc) == "RA101":
                    raise PolicyViolation(str(exc)) from exc
                raise
            if not grant:
                # Les rôles sont inscrits dans le JWT : un retrait doit invalider les jetons émis.
                not_before = await self._principals.bump_tokens_valid_after(conn, principal_id)
                await self._revocations.revoke_principal(
                    conn, principal_id=principal_id, not_before=not_before,
                    expires_at=not_before + self._revocation_horizon, reason="ROLE_REVOKED",
                )
                await self._refresh.revoke_all_for_principal(conn, principal_id, "ROLE_REVOKED")
            await self._audit.record(
                conn,
                event_type="ROLE_GRANTED" if grant else "ROLE_REVOKED",
                outcome="SUCCESS",
                principal_id=principal_id,
                actor_principal_id=actor.sub,
                details={"role": role},
            )
            return await self._principals.get_by_id(conn, principal_id)

    # ------------------------------------------------- comptes et mots de passe
    async def create_user(self, actor: AccessTokenClaims, *, username: str, display_name: str, password: str) -> Principal:
        secret_hash = await self._hasher.hash(password)
        async with self._db.transaction() as conn:
            try:
                principal_id = await self._principals.create_user(conn, username, display_name, secret_hash)
            except asyncpg.UniqueViolationError as exc:
                raise InvalidState("username already taken") from exc
            await self._audit.record(
                conn, event_type="PRINCIPAL_CREATED", outcome="SUCCESS", principal_id=principal_id, actor_principal_id=actor.sub
            )
            return await self._principals.get_by_id(conn, principal_id)

    async def set_password(
        self, actor: AccessTokenClaims, principal_id: UUID, new_password: str, *, current_password: str | None = None
    ) -> None:
        """Réinitialisation par auth.admin, ou changement par l'intéressé (current_password exigé)."""
        if current_password is not None:
            async with self._db.connection() as conn:
                target = await self._principals.get_by_id(conn, principal_id)
            if target is None:
                raise PrincipalNotFound()
            now = datetime.now(UTC)
            if target.is_locked(now):
                raise AccountLocked(int((target.locked_until - now).total_seconds()))
            if not await self._hasher.verify(target.secret_hash, current_password):
                # Même compteur que la connexion : un jeton volé ne permet pas de deviner le mot de passe.
                async with self._db.transaction() as conn:
                    await self._principals.record_login_failure(
                        conn, principal_id,
                        max_failures=self._settings.max_failed_logins, lockout_seconds=self._settings.lockout_seconds,
                    )
                raise PolicyViolation("current password is incorrect")
        secret_hash = await self._hasher.hash(new_password)
        async with self._db.transaction() as conn:
            if not await self._principals.lock(conn, principal_id):
                raise PrincipalNotFound()
            target = await self._principals.get_by_id(conn, principal_id)
            if target.kind is not PrincipalKind.USER:
                raise InvalidState("only human users have a password")
            await self._principals.rotate_secret(conn, principal_id, secret_hash)
            # Nouveau mot de passe => toutes les sessions existantes tombent.
            not_before = await self._principals.bump_tokens_valid_after(conn, principal_id)
            await self._revocations.revoke_principal(
                conn, principal_id=principal_id, not_before=not_before,
                expires_at=not_before + self._revocation_horizon, reason="PASSWORD_CHANGED",
            )
            await self._refresh.revoke_all_for_principal(conn, principal_id, "PASSWORD_CHANGED")
            await self._audit.record(
                conn,
                event_type="PASSWORD_CHANGED" if current_password is not None else "PASSWORD_RESET",
                outcome="SUCCESS",
                principal_id=principal_id,
                actor_principal_id=actor.sub,
            )

    async def sessions(self) -> list:
        async with self._db.connection() as conn:
            return await self._refresh.list_active(conn)

    async def audit_log(self, limit: int, **filters: object) -> list:
        async with self._db.connection() as conn:
            return await self._audit.list_recent(conn, limit, **filters)