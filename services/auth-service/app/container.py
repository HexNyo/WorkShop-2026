"""Racine de composition : instanciation et câblage des dépendances."""

from __future__ import annotations

from dataclasses import dataclass

from app.core.config import Settings
from app.core.db import Database, database_from_settings
from app.core.face import FaceEngine
from app.core.keys import SigningKeys
from app.core.passwords import SecretHasher
from app.domain.policies import AUDIENCE_SELF
from app.repositories.audit import AuditRepository
from app.repositories.faces import FaceRepository
from app.repositories.principals import PrincipalRepository
from app.repositories.refresh_tokens import RefreshTokenRepository
from app.repositories.revocations import RevocationRepository
from app.services.authentication import AuthenticationService
from app.services.bootstrap import BootstrapService
from app.services.client_credentials import ClientCredentialsService
from app.services.face_login import FaceLoginService
from app.services.led import LedController
from app.services.maintenance import MaintenanceWorker
from app.services.principals import PrincipalService
from app.services.tokens import DatabaseRevocationChecker, TokenService
from ra_common.security import StaticKeyResolver, TokenVerifier


@dataclass(slots=True)
class Container:
    settings: Settings
    db: Database
    keys: SigningKeys
    token_verifier: TokenVerifier
    introspection_verifier: TokenVerifier
    authentication: AuthenticationService
    client_credentials: ClientCredentialsService
    principals: PrincipalService
    bootstrap: BootstrapService
    maintenance: MaintenanceWorker
    face_login: FaceLoginService
    led: LedController

    @classmethod
    def build(cls, settings: Settings) -> Container:
        db = database_from_settings(settings)
        keys = SigningKeys.load(
            kid=settings.jwt_key_id,
            private_key_pem_b64=settings.jwt_private_key_pem_b64.get_secret_value(),
            previous_public_keys=settings.jwt_previous_public_keys,
        )
        hasher = SecretHasher(concurrency=settings.password_hash_concurrency)
        principals_repo = PrincipalRepository()
        refresh_repo = RefreshTokenRepository()
        revocations_repo = RevocationRepository()
        audit_repo = AuditRepository()

        tokens = TokenService(keys=keys, issuer=settings.issuer, access_ttl_seconds=settings.access_token_ttl_seconds)
        key_resolver = StaticKeyResolver(keys.public_keys)
        revocation_checker = DatabaseRevocationChecker(db, revocations_repo)
        authentication = AuthenticationService(
            settings=settings,
            db=db,
            hasher=hasher,
            tokens=tokens,
            principals=principals_repo,
            refresh_tokens=refresh_repo,
            revocations=revocations_repo,
            audit=audit_repo,
        )
        led = LedController(settings.esp8266_url)

        return cls(
            settings=settings,
            db=db,
            keys=keys,
            token_verifier=TokenVerifier(
                issuer=settings.issuer,
                audience=AUDIENCE_SELF,
                key_resolver=key_resolver,
                revocation_checker=revocation_checker,
                leeway_seconds=settings.clock_leeway_seconds,
            ),
            introspection_verifier=TokenVerifier(
                issuer=settings.issuer,
                audience=None,
                key_resolver=key_resolver,
                revocation_checker=revocation_checker,
                leeway_seconds=settings.clock_leeway_seconds,
            ),
            authentication=authentication,
            client_credentials=ClientCredentialsService(
                db=db, hasher=hasher, tokens=tokens, principals=principals_repo, audit=audit_repo
            ),
            principals=PrincipalService(
                settings=settings,
                db=db,
                principals=principals_repo,
                refresh_tokens=refresh_repo,
                revocations=revocations_repo,
                audit=audit_repo,
            ),
            bootstrap=BootstrapService(db=db, hasher=hasher, principals=principals_repo, audit=audit_repo),
            maintenance=MaintenanceWorker(
                db=db,
                refresh_tokens=refresh_repo,
                revocations=revocations_repo,
                interval_seconds=settings.maintenance_interval_seconds,
            ),
            face_login=FaceLoginService(
                settings=settings,
                db=db,
                engine=FaceEngine(),
                faces=FaceRepository(),
                principals=principals_repo,
                audit=audit_repo,
                authentication=authentication,
                led=led,
            ),
            led=led,
        )
