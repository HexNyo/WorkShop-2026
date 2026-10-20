from __future__ import annotations

import base64

import numpy as np
import pytest
from pydantic import ValidationError

from app.api.schemas import FaceLoginRequest
from app.core.face import FaceEngine, similarity
from app.services.face_login import FAILURE_COOLDOWN_SECONDS, LOCKOUT_SECONDS, FaceAttemptLimiter


def test_one_retry_then_five_minute_lockout() -> None:
    limiter = FaceAttemptLimiter()
    assert limiter.retry_after("alice", 0) == 0
    assert limiter.record_failure("alice", 0) == (FAILURE_COOLDOWN_SECONDS, False)
    assert limiter.retry_after("alice", 10) == FAILURE_COOLDOWN_SECONDS - 10
    assert limiter.retry_after("bob", 10) == 0, "per username"
    assert limiter.record_failure("alice", 31) == (LOCKOUT_SECONDS, True)
    assert limiter.retry_after("alice", 31 + LOCKOUT_SECONDS - 1) == 1
    # Verrou purgé : de nouveau une tentative + un retry.
    assert limiter.record_failure("alice", 31 + LOCKOUT_SECONDS) == (FAILURE_COOLDOWN_SECONDS, False)


def test_success_or_admin_unlock_resets_and_old_failures_expire() -> None:
    limiter = FaceAttemptLimiter()
    limiter.record_failure("alice", 0)
    limiter.reset("alice")
    assert limiter.retry_after("alice", 1) == 0
    assert limiter.record_failure("alice", 1) == (FAILURE_COOLDOWN_SECONDS, False)
    assert limiter.record_failure("alice", 10_000) == (FAILURE_COOLDOWN_SECONDS, False), "not consecutive anymore"


def test_similarity_is_cosine() -> None:
    a = np.arange(1, 129, dtype=np.float32)
    assert similarity(a.tobytes(), (a * 3).tobytes()) == pytest.approx(1.0)
    assert similarity(a.tobytes(), (-a).tobytes()) == pytest.approx(-1.0)


def test_undecodable_image_is_no_face_not_a_crash() -> None:
    # En-tête JPEG annonçant 4000x4000 > OPENCV_IO_MAX_IMAGE_PIXELS de l'image Docker : cv2.error, pas None.
    huge_header = bytes.fromhex("ffd8ffc0000b080fa00fa0010111")
    for image in (b"", b"not a jpeg", huge_header):
        assert FaceEngine("/nonexistent")._embed(image) is None


def test_face_image_must_be_strict_base64() -> None:
    ok = FaceLoginRequest(username="alice", image=base64.b64encode(b"\xff\xd8jpeg").decode())
    assert ok.image == b"\xff\xd8jpeg"
    for bad in ("not base64!", "", "data:image/jpeg;base64,AAAA"):
        with pytest.raises(ValidationError):
            FaceLoginRequest(username="alice", image=bad)
