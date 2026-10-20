from __future__ import annotations

from app.core.passwords import SecretHasher, generate_refresh_token, hash_refresh_token


async def test_hash_and_verify() -> None:
    hasher = SecretHasher(concurrency=2)
    stored = await hasher.hash("correct horse battery staple")
    assert stored.startswith("$argon2id$")
    assert await hasher.verify(stored, "correct horse battery staple")
    assert not await hasher.verify(stored, "wrong password")
    assert not hasher.needs_rehash(stored)


async def test_unset_or_missing_secret_never_verifies() -> None:
    hasher = SecretHasher(concurrency=1)
    assert not await hasher.verify("!", "anything")
    assert not await hasher.verify(None, "anything")
    assert not await hasher.verify("not-a-hash", "anything")


def test_refresh_tokens_are_random_and_hashed() -> None:
    first, second = generate_refresh_token(), generate_refresh_token()
    assert first != second and len(first) >= 64
    assert len(hash_refresh_token(first)) == 32
    assert hash_refresh_token(first) == hash_refresh_token(first)
