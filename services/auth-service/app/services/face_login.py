"""Connexion en deux étapes : identifiant + visage (pre_auth_token), puis mot de passe."""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from dataclasses import dataclass
from math import ceil
from uuid import UUID

from app.core.config import Settings
from app.core.db import Database
from app.core.face import FaceEngine, similarity
from app.domain.errors import (
    AccountLocked,
    FaceRejected,
    InvalidCredentials,
    InvalidState,
    NoUsableFace,
    PreAuthInvalid,
    PrincipalNotFound,
)
from app.domain.models import LoginResult, Principal, PrincipalKind
from app.repositories.audit import AuditRepository
from app.repositories.faces import FaceRepository
from app.repositories.principals import PrincipalRepository
from app.services.authentication import AuthenticationService
from app.services.led import LedController
from ra_common.logging import log_event

logger = logging.getLogger("auth.face_login")

FAILURE_COOLDOWN_SECONDS = 30  # LED rouge fixe + UI verrouillée
LOCKOUT_SECONDS = 300  # au 2e échec consécutif
MAX_CONSECUTIVE_FAILURES = 2
PRE_AUTH_TTL_SECONDS = 120
MAX_TRACKED = 10_000  # borne mémoire face à un balayage d'identifiants


@dataclass(slots=True)
class _Attempts:
    failures: int = 0
    blocked_until: float = 0.0


class FaceAttemptLimiter:
    """Échecs faciaux consécutifs par identifiant (existant ou non : pas d'énumération).

    shortcut: état en mémoire d'un seul réplica, perdu au redémarrage ; passer en base si auth-service est répliqué.
    """

    def __init__(self) -> None:
        self._attempts: dict[str, _Attempts] = {}

    def retry_after(self, username: str, now: float) -> int:
        state = self._attempts.get(username)
        return ceil(state.blocked_until - now) if state and state.blocked_until > now else 0

    def record_failure(self, username: str, now: float) -> tuple[int, bool]:
        """Renvoie (secondes d'attente, verrouillage de 5 min atteint)."""
        if len(self._attempts) > MAX_TRACKED:
            self._attempts = {k: v for k, v in self._attempts.items() if v.blocked_until + LOCKOUT_SECONDS > now}
        state = self._attempts.setdefault(username, _Attempts())
        # Verrou déjà purgé, ou échec précédent trop ancien pour être « consécutif » : on repart de zéro.
        if state.failures >= MAX_CONSECUTIVE_FAILURES or state.blocked_until + LOCKOUT_SECONDS < now:
            state.failures = 0
        state.failures += 1
        locked = state.failures >= MAX_CONSECUTIVE_FAILURES
        wait = LOCKOUT_SECONDS if locked else FAILURE_COOLDOWN_SECONDS
        state.blocked_until = now + wait
        return wait, locked

    def reset(self, username: str) -> None:
        self._attempts.pop(username, None)


class FaceLoginService:
    def __init__(
        self,
        *,
        settings: Settings,
        db: Database,
        engine: FaceEngine,
        faces: FaceRepository,
        principals: PrincipalRepository,
        audit: AuditRepository,
        authentication: AuthenticationService,
        led: LedController,
    ) -> None:
        self._settings = settings
        self._db = db
        self._engine = engine
        self._faces = faces
        self._principals = principals
        self._audit = audit
        self._authentication = authentication
        self._led = led
        self._limiter = FaceAttemptLimiter()
        self._pre_auth: dict[str, tuple[str, float]] = {}  # jeton -> (identifiant, expiration monotone)
        # Vérifier puis compter atomiquement : deux requêtes parallèles ne doublent pas l'essai autorisé.
        self._verify_lock = asyncio.Lock()

    # ------------------------------------------------------------ étape 1
    async def verify_face(self, username: str, image: bytes, *, client_ip: str | None) -> tuple[str, int]:
        normalized = username.strip().lower()
        async with self._verify_lock:
            wait = self._limiter.retry_after(normalized, time.monotonic())
            if wait:
                raise FaceRejected(wait, locked=True)

            async with self._db.connection() as conn:
                principal = await self._principals.get_by_username(conn, normalized)
                reference = await self._faces.get(conn, principal.id) if principal else None
            # Empreinte toujours calculée : même coût qu'il y ait un compte ou non.
            probe = await self._engine.embed(image)
            score = similarity(probe, reference) if probe is not None and reference is not None else 0.0
            eligible = principal is not None and principal.kind is PrincipalKind.USER and principal.is_active

            if not eligible or score < self._settings.face_match_threshold:
                wait, locked = self._limiter.record_failure(normalized, time.monotonic())
                self._led.send("RED_SOLID_30S")
                await self._record(
                    "FACE_VERIFY_FAILURE", "FAILURE", principal, client_ip,
                    {"username": normalized[:64], "face_detected": probe is not None, "score": round(score, 3), "locked": locked},
                )
                raise FaceRejected(wait, locked=locked)

            self._limiter.reset(normalized)
            now = time.monotonic()
            self._pre_auth = {k: v for k, v in self._pre_auth.items() if v[1] > now}
            token = secrets.token_urlsafe(32)
            self._pre_auth[token] = (normalized, now + PRE_AUTH_TTL_SECONDS)
        self._led.send("GREEN_BLINK")
        await self._record("FACE_VERIFY_SUCCESS", "SUCCESS", principal, client_ip, {"score": round(score, 3)})
        return token, PRE_AUTH_TTL_SECONDS

    # ------------------------------------------------------------ étape 2
    async def verify_password(
        self, pre_auth_token: str, password: str, *, client_ip: str | None, user_agent: str | None
    ) -> LoginResult:
        entry = self._pre_auth.pop(pre_auth_token, None)  # usage unique, même en cas d'échec
        if entry is None or entry[1] < time.monotonic():
            raise PreAuthInvalid()
        try:
            result = await self._authentication.login(entry[0], password, client_ip=client_ip, user_agent=user_agent)
        except (InvalidCredentials, AccountLocked):
            self._led.send("RED_BLINK_10")
            raise
        self._led.send("GREEN_SOLID_30S")
        return result

    # ------------------------------------------------------- administration
    def blocked_seconds(self, username: str) -> int:
        return self._limiter.retry_after(username, time.monotonic())

    def unlock(self, username: str) -> None:
        self._limiter.reset(username)

    async def enroll(self, actor_sub: str | None, principal_id: UUID, image: bytes) -> Principal:
        embedding = await self._engine.embed(image)
        if embedding is None:
            raise NoUsableFace()
        async with self._db.transaction() as conn:
            target = await self._principals.get_by_id(conn, principal_id)
            if target is None:
                raise PrincipalNotFound()
            if target.kind is not PrincipalKind.USER:
                raise InvalidState("only human users can enrol a face")
            await self._faces.upsert(conn, principal_id, embedding, UUID(actor_sub) if actor_sub else None)
            await self._audit.record(
                conn, event_type="FACE_ENROLLED", outcome="SUCCESS", principal_id=principal_id, actor_principal_id=actor_sub
            )
            enrolled = await self._principals.get_by_id(conn, principal_id)
        log_event(logger, logging.INFO, "auth.face_enrolled", "face enrolled", target_principal_id=str(principal_id))
        return enrolled

    async def delete_face(self, actor_sub: str, principal_id: UUID) -> Principal:
        """Effacement de la donnée biométrique (RGPD art. 17) ; idempotent."""
        async with self._db.transaction() as conn:
            if await self._principals.get_by_id(conn, principal_id) is None:
                raise PrincipalNotFound()
            if await self._faces.delete(conn, principal_id):
                await self._audit.record(
                    conn, event_type="FACE_DELETED", outcome="SUCCESS", principal_id=principal_id, actor_principal_id=actor_sub
                )
            return await self._principals.get_by_id(conn, principal_id)

    async def enroll_username(self, username: str, image: bytes) -> Principal:
        async with self._db.connection() as conn:
            principal = await self._principals.get_by_username(conn, username.strip().lower())
        if principal is None:
            raise PrincipalNotFound()
        return await self.enroll(None, principal.id, image)

    async def _record(
        self, event_type: str, outcome: str, principal: Principal | None, client_ip: str | None, details: dict
    ) -> None:
        async with self._db.transaction() as conn:
            await self._audit.record(
                conn,
                event_type=event_type,
                outcome=outcome,
                principal_id=principal.id if principal else None,
                client_ip=client_ip,
                details=details,
            )
