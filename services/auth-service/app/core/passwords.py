"""Hachage Argon2id des secrets et génération des jetons de rafraîchissement opaques."""

from __future__ import annotations

import asyncio
import hashlib
import secrets

import anyio.to_thread
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

UNSET_SECRET = "!"


class SecretHasher:
    """Argon2id (paramètres argon2-cffi par défaut : t=3, m=64 Mio, p=4).

    Le calcul est déporté dans un thread et borné par un sémaphore pour ne
    bloquer ni la boucle d'événements ni la mémoire du conteneur.
    """

    def __init__(self, concurrency: int = 4) -> None:
        self._hasher = PasswordHasher()
        self._semaphore = asyncio.Semaphore(concurrency)
        # Empreinte factice : temps de réponse constant quand le principal n'existe pas.
        self._dummy_hash = self._hasher.hash(secrets.token_urlsafe(32))

    async def hash(self, secret: str) -> str:
        async with self._semaphore:
            return await anyio.to_thread.run_sync(self._hasher.hash, secret)

    async def verify(self, stored_hash: str | None, secret: str) -> bool:
        target = stored_hash if stored_hash and stored_hash != UNSET_SECRET else self._dummy_hash
        async with self._semaphore:
            valid = await anyio.to_thread.run_sync(self._safe_verify, target, secret)
        return valid and target is stored_hash

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except InvalidHashError:
            return True

    def _safe_verify(self, stored_hash: str, secret: str) -> bool:
        try:
            return self._hasher.verify(stored_hash, secret)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False


def generate_refresh_token() -> str:
    return secrets.token_urlsafe(48)


def hash_refresh_token(token: str) -> bytes:
    return hashlib.sha256(token.encode("utf-8")).digest()
