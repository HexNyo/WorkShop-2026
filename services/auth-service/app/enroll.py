"""Enrôlement facial hors ligne, pour amorcer le premier administrateur (personne ne peut se
connecter avant d'avoir un visage enrôlé) :

    docker compose exec -T auth-service python -m app.enroll admin < visage.jpg
"""

from __future__ import annotations

import asyncio
import sys

from app.container import Container
from app.core.config import Settings
from app.domain.errors import NoUsableFace, PrincipalNotFound


async def main(username: str, image: bytes) -> int:
    container = Container.build(Settings())
    await container.db.connect()
    try:
        principal = await container.face_login.enroll_username(username, image)
    except NoUsableFace:
        print("exactly one face must be visible in the image", file=sys.stderr)
        return 1
    except PrincipalNotFound:
        print(f"unknown user: {username}", file=sys.stderr)
        return 1
    finally:
        await container.db.close()
        await container.led.close()
    print(f"face enrolled for {principal.username}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit("usage: python -m app.enroll <username> < photo.jpg")
    sys.exit(asyncio.run(main(sys.argv[1], sys.stdin.buffer.read())))
