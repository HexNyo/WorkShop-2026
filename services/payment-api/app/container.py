"""Racine de composition : instanciation et câblage des dépendances."""

from __future__ import annotations

from dataclasses import dataclass, field

from ra_common.db import Database
from ra_common.security.resource_server import ResourceServerSecurity
from ra_common.sse import EventBroadcaster, StreamTicketSigner

from app.core.config import Settings
from app.repositories.accounts import AccountRepository
from app.repositories.operations import FlagRepository, IntegrityRepository, MaintenanceRepository
from app.repositories.transactions import TransactionRepository
from app.services.administration import AdministrationService
from app.services.events import TransactionEventListener, TransactionEventPublisher
from app.services.faults import FaultInjector
from app.services.integrity import IntegrityService
from app.services.rate_limit import SlidingWindowLimiter
from app.services.runtime_flags import RuntimeFlagsProvider
from app.services.transactions import TransactionService


@dataclass(slots=True)
class Container:
    settings: Settings
    db: Database
    maint_db: Database
    security: ResourceServerSecurity
    flags: RuntimeFlagsProvider
    transactions: TransactionService
    integrity: IntegrityService
    administration: AdministrationService
    broadcaster: EventBroadcaster
    event_listener: TransactionEventListener
    tickets: StreamTicketSigner
    rate_limiter: SlidingWindowLimiter
    integrity_limiter: SlidingWindowLimiter
    faults: FaultInjector | None
    accounts_repository: AccountRepository
    # Référentiel des devises, chargé au démarrage (partagé par référence).
    currencies: dict[str, int] = field(default_factory=dict)

    @classmethod
    def build(cls, settings: Settings) -> Container:
        db = Database(
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name,
            user=settings.db_user,
            password=settings.db_password.get_secret_value(),
            application_name=settings.service_name,
            min_size=settings.db_pool_min_size,
            max_size=settings.db_pool_max_size,
            connect_timeout_seconds=settings.db_connect_timeout_seconds,
        )
        maint_db = Database(
            host=settings.db_host,
            port=settings.db_port,
            database=settings.db_name,
            user=settings.db_maint_user,
            password=settings.db_maint_password.get_secret_value(),
            application_name=f"{settings.service_name}-maint",
            min_size=1,
            max_size=settings.db_maint_pool_max_size,
            connect_timeout_seconds=settings.db_connect_timeout_seconds,
            command_timeout_seconds=60,
        )
        currencies: dict[str, int] = {}
        accounts = AccountRepository()
        transactions = TransactionRepository()
        flag_repository = FlagRepository()
        maintenance = MaintenanceRepository()
        flags = RuntimeFlagsProvider(db, flag_repository, settings.flags_cache_seconds)
        broadcaster = EventBroadcaster()
        integrity = IntegrityService(db=db, repository=IntegrityRepository(), settings=settings)

        return cls(
            settings=settings,
            db=db,
            maint_db=maint_db,
            security=ResourceServerSecurity(
                auth_base_url=settings.auth_base_url,
                issuer=settings.auth_issuer,
                audience=settings.auth_audience,
                client_id=settings.client_id,
                client_secret=settings.client_secret.get_secret_value(),
                poll_interval_seconds=settings.revocation_poll_seconds,
                leeway_seconds=settings.clock_leeway_seconds,
            ),
            flags=flags,
            transactions=TransactionService(
                db=db,
                accounts=accounts,
                transactions=transactions,
                flags=flags,
                events=TransactionEventPublisher(transactions, currencies),
                currencies=currencies,
            ),
            integrity=integrity,
            administration=AdministrationService(
                maint_db=maint_db,
                app_db=db,
                flags_repository=flag_repository,
                maintenance=maintenance,
                flags=flags,
                integrity=integrity,
            ),
            broadcaster=broadcaster,
            event_listener=TransactionEventListener(db, broadcaster),
            tickets=StreamTicketSigner(
                settings.stream_ticket_secret.get_secret_value().encode(),
                ttl_seconds=settings.stream_ticket_ttl_seconds,
                purpose="payment-api-sse",
            ),
            rate_limiter=SlidingWindowLimiter(),
            integrity_limiter=SlidingWindowLimiter(),
            faults=(
                FaultInjector(app_db=db, maint_db=maint_db, maintenance=maintenance, currencies=currencies)
                if settings.chaos_lab_enabled
                else None
            ),
            accounts_repository=accounts,
            currencies=currencies,
        )

    async def start(self) -> None:
        await self.db.connect()
        await self.maint_db.connect()
        async with self.db.connection() as conn:
            self.currencies.update(await self.accounts_repository.currencies(conn))
        await self.flags.get()
        await self.security.start()
        self.event_listener.start()

    async def stop(self) -> None:
        if self.faults is not None:
            await self.faults.clear_all()
        await self.event_listener.stop()
        await self.security.stop()
        await self.maint_db.close()
        await self.db.close()
