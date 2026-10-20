"""Reconnaissance faciale CPU : détection YuNet + empreinte SFace (OpenCV, ~40 Mo, < 50 ms)."""

from __future__ import annotations

import asyncio

import cv2
import numpy as np

MODEL_DIR = "/srv/models"
DETECTOR_MODEL = "face_detection_yunet_2023mar.onnx"
RECOGNIZER_MODEL = "face_recognition_sface_2021dec.onnx"


def similarity(a: bytes, b: bytes) -> float:
    """Cosinus entre deux empreintes SFace (seuil de référence OpenCV : 0,363)."""
    va, vb = np.frombuffer(a, np.float32), np.frombuffer(b, np.float32)
    return float(va @ vb / (np.linalg.norm(va) * np.linalg.norm(vb)))


class FaceEngine:
    def __init__(self, model_dir: str = MODEL_DIR) -> None:
        self._model_dir = model_dir
        self._models: tuple[cv2.FaceDetectorYN, cv2.FaceRecognizerSF] | None = None
        # Les objets OpenCV ne sont pas thread-safe : une inférence à la fois.
        self._lock = asyncio.Lock()

    def _embed(self, image_bytes: bytes) -> bytes | None:
        try:  # vide, corrompu ou au-delà de OPENCV_IO_MAX_IMAGE_PIXELS : cv2 lève au lieu de rendre None
            image = cv2.imdecode(np.frombuffer(image_bytes, np.uint8), cv2.IMREAD_COLOR)
        except cv2.error:
            return None
        if image is None:
            return None
        if self._models is None:  # chargement paresseux : les tests unitaires n'ont pas les modèles
            self._models = (
                cv2.FaceDetectorYN.create(f"{self._model_dir}/{DETECTOR_MODEL}", "", (320, 320), 0.9),
                cv2.FaceRecognizerSF.create(f"{self._model_dir}/{RECOGNIZER_MODEL}", ""),
            )
        detector, recognizer = self._models
        detector.setInputSize((image.shape[1], image.shape[0]))
        _, faces = detector.detect(image)
        # Exactement un visage : refuse les captures vides ou avec une personne en arrière-plan.
        if faces is None or len(faces) != 1:
            return None
        return recognizer.feature(recognizer.alignCrop(image, faces[0])).astype(np.float32).tobytes()

    async def embed(self, image_bytes: bytes) -> bytes | None:
        """Empreinte de 512 octets, ou None si l'image ne contient pas exactement un visage."""
        async with self._lock:
            return await asyncio.to_thread(self._embed, image_bytes)
