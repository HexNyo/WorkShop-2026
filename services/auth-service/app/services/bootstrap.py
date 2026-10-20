"""Amorçage des secrets des principaux pré-créés à partir de l'environnement.

Pour chaque principal `nom-du-principal`, la variable lue est
`AUTH_BOOTSTRAP_NOM_DU_PRINCIPAL_SECRET`.
  * secret non initialisé ('!') + variable fournie => secret posé, principal activé ;
  * secret existant différent de la variable        => rotation (sans réactivation) ;
  * variable absente                                => principal laissé tel quel.
Un principal désactivé par la remédiation n'est jamais réactivé par l'amorçage.
"""

from __future__ import annotations

import logging
import os
import re
from collections.abc import Mapping

from app.core.config import MIN_SECRET_LENGTH
from app.core.db import Database
from app.core.passwords import SecretHasher
from app.repositories.audit import AuditRepository
from app.repositories.principals import PrincipalRepository
from ra_common.logging import log_event

logger = logging.getLogger("auth.bootstrap")
_LOCK_KEY = 0x52414254  # "RABT" — sérialise l'amorçage entre réplicas


class BootstrapError(RuntimeError):
    pass


def bootstrap_variable(username: str) -> str:
    return "AUTH_BOOTSTRAP_" + re.sub(r"[^A-Z0-9]", "_", username.upper()) + "_SECRET"


class BootstrapService:
    def __init__(
        self,
        *,
        db: Database,
        hasher: SecretHasher,
        principals: PrincipalRepository,
        audit: AuditRepository,
        environ: Mapping[str, str] | None = None,
    ) -> None:
        self._db = db
        self._hasher = hasher
        self._principals = principals
        self._audit = audit
        self._environ = environ if environ is not None else os.environ

    async def run(self) -> None:
        initialised = rotated = pending = 0
        async with self._db.transaction() as conn:
            await conn.execute("SELECT pg_advisory_xact_lock($1)", _LOCK_KEY)
            for principal in await self._principals.list_all(conn):
                variable = bootstrap_variable(principal.username)
                secret = self._environ.get(variable, "")
                if not secret:
                    if not principal.has_secret:
                        pending += 1
                        log_event(
                            logger,
                            logging.WARNING,
                            "auth.bootstrap_pending",
                            "principal stays inactive: no bootstrap secret provided",
                            username=principal.username,
                            variable=variable,
                        )
                    continue
                if len(secret) < MIN_SECRET_LENGTH:
                    raise BootstrapError(f"{variable} must contain at least {MIN_SECRET_LENGTH} characters")

                if not principal.has_secret:
                    if await self._principals.initialise_secret(conn, principal.id, await self._hasher.hash(secret)):
                        initialised += 1
                        await self._audit.record(
                            conn, event_type="BOOTSTRAP_SECRET_SET", outcome="SUCCESS", principal_id=principal.id
                        )
                elif not await self._hasher.verify(principal.secret_hash, secret):
                    await self._principals.rotate_secret(conn, principal.id, await self._hasher.hash(secret))
                    rotated += 1
                    await self._audit.record(
                        conn, event_type="BOOTSTRAP_SECRET_ROTATED", outcome="SUCCESS", principal_id=principal.id
                    )
        log_event(
            logger,
            logging.INFO,
            "auth.bootstrap_completed",
            "principal bootstrap completed",
            initialised=initialised,
            rotated=rotated,
            pending=pending,
        )
