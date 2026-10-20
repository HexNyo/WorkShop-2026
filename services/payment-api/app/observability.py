"""Métriques métier de payment-api (préfixe ra_)."""

from prometheus_client import Counter, Gauge, Histogram

TRANSACTIONS = Counter("ra_transactions_total", "Transactions par statut final", ["status", "synthetic"])
PROCESSING = Histogram(
    "ra_transaction_processing_seconds",
    "Durée de traitement d'une demande de transaction",
    ["outcome"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5),
)
AMOUNT = Counter("ra_transaction_amount_minor_total", "Montants exécutés (unités mineures)", ["currency"])
REPLAYS = Counter("ra_idempotent_replays_total", "Rejeux idempotents servis")
INTEGRITY = Gauge("ra_integrity_check_passed", "Dernier résultat de chaque contrôle d'intégrité (1 = OK)", ["check"])
DIVERGENCE = Counter("ra_ledger_divergence_total", "Écritures refusées pour divergence solde / grand livre")
WRITE_MODE = Gauge("ra_write_mode", "Mode d'écriture courant (1 = actif)", ["mode"])
POOL = Gauge("ra_db_pool_connections", "Connexions des pools PostgreSQL", ["pool", "state"])
SSE_SUBSCRIBERS = Gauge("ra_sse_subscribers", "Abonnés SSE connectés")
FAULTS = Gauge("ra_lab_fault_active", "Pannes de laboratoire actives", ["type"])
