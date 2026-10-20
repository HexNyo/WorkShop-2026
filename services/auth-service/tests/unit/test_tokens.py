from __future__ import annotations

import base64
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from app.core.keys import KeyConfigurationError, SigningKeys
from app.services.tokens import TokenService
from ra_common.security import AccessTokenClaims, StaticKeyResolver, TokenError, TokenVerifier

ISSUER = "https://auth.test.local"


class FakeRevocations:
    def __init__(self, revoked: set[str] | None = None) -> None:
        self.revoked = revoked or set()

    async def is_revoked(self, claims: AccessTokenClaims) -> bool:
        return claims.jti in self.revoked


def _verifier(keys: SigningKeys, audience: str | None = "payment-api", revoked: set[str] | None = None) -> TokenVerifier:
    return TokenVerifier(
        issuer=ISSUER,
        audience=audience,
        key_resolver=StaticKeyResolver(keys.public_keys),
        revocation_checker=FakeRevocations(revoked),
        leeway_seconds=0,
    )


async def test_issued_token_round_trips(signing_keys, principal_factory) -> None:
    service = TokenService(keys=signing_keys, issuer=ISSUER, access_ttl_seconds=300)
    issued = service.issue(principal_factory(), audiences=("payment-api", "assistant"), roles=("payment.customer",))
    claims = await _verifier(signing_keys).verify(issued.token)
    assert claims.sub == "00000000-0000-4000-8000-000000000002"
    assert claims.roles == ("payment.customer",)
    assert claims.aud == ("payment-api", "assistant")
    assert claims.exp - claims.iat == 300
    assert claims.typ == "access" and claims.pkind == "USER"
    assert jwt.get_unverified_header(issued.token)["kid"] == "test-kid"


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ({"aud": ["remediation-control"]}, "wrong_audience"),
        ({"iss": "https://evil.example"}, "wrong_issuer"),
        ({"exp": int(time.time()) - 60}, "expired"),
        ({"nbf": int(time.time()) + 3600}, "not_yet_valid"),
        ({"typ": "refresh"}, "invalid_claims"),
    ],
)
async def test_invalid_claims_are_rejected(signing_keys, mutation, reason) -> None:
    now = int(time.time())
    payload = {
        "iss": ISSUER, "sub": "s", "aud": ["payment-api"], "iat": now, "nbf": now, "exp": now + 300,
        "jti": "j", "typ": "access", "pkind": "USER", "name": "n", "roles": [],
    }
    payload.update(mutation)
    token = jwt.encode(payload, signing_keys.private_key, algorithm="RS256", headers={"kid": "test-kid"})
    with pytest.raises(TokenError) as excinfo:
        await _verifier(signing_keys).verify(token)
    assert excinfo.value.reason == reason


async def test_revoked_token_is_rejected(signing_keys, principal_factory) -> None:
    issued = TokenService(keys=signing_keys, issuer=ISSUER, access_ttl_seconds=300).issue(
        principal_factory(), audiences=("payment-api",), roles=()
    )
    with pytest.raises(TokenError) as excinfo:
        await _verifier(signing_keys, revoked={str(issued.jti)}).verify(issued.token)
    assert excinfo.value.reason == "revoked"


async def test_foreign_signature_and_alg_none_are_rejected(signing_keys) -> None:
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = int(time.time())
    payload = {"iss": ISSUER, "sub": "s", "aud": "payment-api", "iat": now, "nbf": now, "exp": now + 60, "jti": "j"}
    forged = jwt.encode(payload, other, algorithm="RS256", headers={"kid": "test-kid"})
    with pytest.raises(TokenError, match="invalid"):
        await _verifier(signing_keys).verify(forged)

    unsigned = jwt.encode(payload, None, algorithm="none")
    with pytest.raises(TokenError, match="unsupported_algorithm"):
        await _verifier(signing_keys).verify(unsigned)

    hs256 = jwt.encode(payload, "secret-secret-secret-secret-secret", algorithm="HS256", headers={"kid": "test-kid"})
    with pytest.raises(TokenError, match="unsupported_algorithm"):
        await _verifier(signing_keys).verify(hs256)


async def test_unknown_kid_and_garbage(signing_keys, principal_factory) -> None:
    issued = TokenService(keys=signing_keys, issuer=ISSUER, access_ttl_seconds=300).issue(
        principal_factory(), audiences=("payment-api",), roles=()
    )
    verifier = TokenVerifier(
        issuer=ISSUER, audience="payment-api", key_resolver=StaticKeyResolver({}), revocation_checker=FakeRevocations()
    )
    with pytest.raises(TokenError, match="unknown_key"):
        await verifier.verify(issued.token)
    with pytest.raises(TokenError, match="malformed"):
        await verifier.verify("not-a-jwt")


async def test_introspection_verifier_accepts_any_audience(signing_keys, principal_factory) -> None:
    issued = TokenService(keys=signing_keys, issuer=ISSUER, access_ttl_seconds=300).issue(
        principal_factory(), audiences=("remediation-control",), roles=("svc.detector",)
    )
    claims = await _verifier(signing_keys, audience=None).verify(issued.token)
    assert claims.aud == ("remediation-control",)


def test_jwks_publishes_current_and_previous_keys(private_key_b64) -> None:
    previous = rsa.generate_private_key(public_exponent=65537, key_size=2048).public_key()
    previous_pem = previous.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    keys = SigningKeys.load(
        kid="current",
        private_key_pem_b64=private_key_b64,
        previous_public_keys=f"old:{base64.b64encode(previous_pem).decode()}",
    )
    published = {key["kid"]: key for key in keys.jwks()["keys"]}
    assert set(published) == {"current", "old"}
    assert all(key["alg"] == "RS256" and key["use"] == "sig" and key["kty"] == "RSA" for key in published.values())
    assert all("d" not in key for key in published.values()), "private material must never be published"


def test_key_configuration_errors(private_key_b64) -> None:
    weak = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    weak_b64 = base64.b64encode(
        weak.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    ).decode()
    with pytest.raises(KeyConfigurationError, match="at least 2048"):
        SigningKeys.load(kid="k", private_key_pem_b64=weak_b64)
    with pytest.raises(KeyConfigurationError, match="base64"):
        SigningKeys.load(kid="k", private_key_pem_b64="%%%not-base64%%%")
    with pytest.raises(KeyConfigurationError, match="distinct kids"):
        SigningKeys.load(kid="k", private_key_pem_b64=private_key_b64, previous_public_keys="k:AAAA")
