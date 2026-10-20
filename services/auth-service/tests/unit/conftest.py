from __future__ import annotations

import base64
from datetime import UTC, datetime
from uuid import UUID

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.keys import SigningKeys
from app.domain.models import Principal, PrincipalKind


def _pem_b64(private_key: rsa.RSAPrivateKey) -> str:
    pem = private_key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return base64.b64encode(pem).decode()


@pytest.fixture(scope="session")
def rsa_key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture(scope="session")
def private_key_b64(rsa_key: rsa.RSAPrivateKey) -> str:
    return _pem_b64(rsa_key)


@pytest.fixture(scope="session")
def signing_keys(private_key_b64: str) -> SigningKeys:
    return SigningKeys.load(kid="test-kid", private_key_pem_b64=private_key_b64)


def make_principal(
    *,
    kind: PrincipalKind = PrincipalKind.USER,
    roles: tuple[str, ...] = ("payment.customer",),
    privileged: bool = False,
    principal_id: str = "00000000-0000-4000-8000-000000000002",
) -> Principal:
    now = datetime.now(UTC)
    return Principal(
        id=UUID(principal_id),
        kind=kind,
        username="alice",
        display_name="Alice Démo",
        secret_hash="$argon2id$v=19$m=65536,t=3,p=4$placeholder",
        is_active=True,
        failed_login_count=0,
        locked_until=None,
        tokens_valid_after=datetime.min.replace(tzinfo=UTC),
        last_login_at=None,
        created_at=now,
        roles=roles,
        is_privileged=privileged,
    )


@pytest.fixture
def principal_factory():
    return make_principal
