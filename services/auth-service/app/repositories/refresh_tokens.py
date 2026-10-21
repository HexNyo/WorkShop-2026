"""Jetons de rafraîchissement : seule l'empreinte SHA-256 est stockée."""

from __future__ import annotations

import ipaddress
from datetime import datetime
from uuid import UUID, uuid4

from ra_common.db import Connection, Record

from app.domain.models import RefreshToken

_COLUMNS = "id, family_id, principal_id, issued_at, expires_at, used_at, revoked_at"


def _to_token(row: Record) -> RefreshToken:
    return RefreshToken(
        id=UUID(str(row["id"])),
        family_id=UUID(str(row["family_id"])),
        principal_id=UUID(str(row["principal_id"])),
        issued_at=row["issued_at"],
        expires_at=row["expires_at"],
        used_at=row["used_at"],
        revoked_at=row["revoked_at"],
    )


def _ip(value: str | None) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    if not value:
        return None
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


class RefreshTokenRepository:
    async def create(
        self,
        conn: Connection,
        *,
        family_id: UUID,
        principal_id: UUID,
        token_hash: bytes,
        expires_at: datetime,
        client_ip: str | None,
        user_agent: str | None,
    ) -> UUID:
        token_id = uuid4()
        await conn.execute(
            """
            INSERT INTO ra_auth.refresh_tokens (id, family_id, principal_id, token_hash, expires_at, client_ip, user_agent)
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            """,
            token_id,
            family_id,
            principal_id,
            token_hash,
            expires_at,
            _ip(client_ip),
            (user_agent or "")[:256] or None,
        )
        return token_id

    async def consume(self, conn: Connection, token_hash: bytes) -> RefreshToken | None:
        """Échange atomique : un jeton ne peut être consommé qu'une seule fois (seul l'UPDATE gagnant le relit)."""
        result = await conn.execute(
            """
            UPDATE ra_auth.refresh_tokens SET used_at = CURRENT_TIMESTAMP(6)
             WHERE token_hash = $1 AND used_at IS NULL AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP(6)
            """,
            token_hash,
        )
        if not result.endswith(" 1"):
            return None
        return await self.find(conn, token_hash)

    async def find(self, conn: Connection, token_hash: bytes) -> RefreshToken | None:
        row = await conn.fetchrow(f"SELECT {_COLUMNS} FROM ra_auth.refresh_tokens WHERE token_hash = $1", token_hash)
        return _to_token(row) if row else None

    async def revoke_family(self, conn: Connection, family_id: UUID, reason: str) -> int:
        result = await conn.execute(
            """
            UPDATE ra_auth.refresh_tokens SET revoked_at = CURRENT_TIMESTAMP(6), revoke_reason = $2
             WHERE family_id = $1 AND revoked_at IS NULL
            """,
            family_id,
            reason,
        )
        return int(result.split()[-1])

    async def revoke_all_for_principal(self, conn: Connection, principal_id: UUID, reason: str) -> int:
        result = await conn.execute(
            """
            UPDATE ra_auth.refresh_tokens SET revoked_at = CURRENT_TIMESTAMP(6), revoke_reason = $2
             WHERE principal_id = $1 AND revoked_at IS NULL AND expires_at > CURRENT_TIMESTAMP(6)
            """,
            principal_id,
            reason,
        )
        return int(result.split()[-1])

    async def list_active(self, conn: Connection) -> list[Record]:
        """Une ligne par session : le jeton courant (non consommé) de chaque famille."""
        return await conn.fetch(
            """
            SELECT rt.family_id, rt.principal_id, p.username, p.display_name, rt.issued_at AS last_refresh,
                   rt.expires_at, rt.client_ip, rt.user_agent
              FROM ra_auth.refresh_tokens rt JOIN ra_auth.principals p ON p.id = rt.principal_id
             WHERE rt.used_at IS NULL AND rt.revoked_at IS NULL AND rt.expires_at > CURRENT_TIMESTAMP(6)
             ORDER BY rt.issued_at DESC
            """
        )

    async def purge_expired(self, conn: Connection, *, older_than_seconds: int) -> int:
        result = await conn.execute(
            "DELETE FROM ra_auth.refresh_tokens WHERE expires_at < CURRENT_TIMESTAMP(6) - INTERVAL $1 SECOND",
            older_than_seconds,
        )
        return int(result.split()[-1])
