"""Matériel cryptographique de signature (RS256) et publication JWKS."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

MIN_RSA_BITS = 2048


class KeyConfigurationError(ValueError):
    pass


def _decode_pem(value: str, what: str) -> bytes:
    try:
        return base64.b64decode(value.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyConfigurationError(f"{what} is not valid base64") from exc


@dataclass(frozen=True, slots=True)
class SigningKeys:
    kid: str
    private_key: rsa.RSAPrivateKey
    public_keys: dict[str, rsa.RSAPublicKey]

    @classmethod
    def load(cls, *, kid: str, private_key_pem_b64: str, previous_public_keys: str = "") -> SigningKeys:
        pem = _decode_pem(private_key_pem_b64, "AUTH_JWT_PRIVATE_KEY_PEM_B64")
        try:
            private_key = serialization.load_pem_private_key(pem, password=None)
        except (ValueError, TypeError) as exc:
            raise KeyConfigurationError("AUTH_JWT_PRIVATE_KEY_PEM_B64 is not an unencrypted PEM private key") from exc
        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise KeyConfigurationError("signing key must be an RSA key")
        if private_key.key_size < MIN_RSA_BITS:
            raise KeyConfigurationError(f"RSA signing key must be at least {MIN_RSA_BITS} bits")

        public_keys: dict[str, rsa.RSAPublicKey] = {kid: private_key.public_key()}
        for raw_entry in previous_public_keys.split(","):
            entry = raw_entry.strip()
            if not entry:
                continue
            previous_kid, separator, encoded = entry.partition(":")
            if not separator or not previous_kid or previous_kid == kid:
                raise KeyConfigurationError("AUTH_JWT_PREVIOUS_PUBLIC_KEYS entries must be 'kid:base64pem' with distinct kids")
            try:
                public_key = serialization.load_pem_public_key(_decode_pem(encoded, f"previous key {previous_kid}"))
            except ValueError as exc:
                raise KeyConfigurationError(f"previous key {previous_kid} is not a PEM public key") from exc
            if not isinstance(public_key, rsa.RSAPublicKey):
                raise KeyConfigurationError(f"previous key {previous_kid} must be an RSA key")
            public_keys[previous_kid] = public_key
        return cls(kid=kid, private_key=private_key, public_keys=public_keys)

    def jwks(self) -> dict[str, Any]:
        keys = []
        for kid, public_key in self.public_keys.items():
            jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
            jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
            keys.append(jwk)
        return {"keys": keys}
