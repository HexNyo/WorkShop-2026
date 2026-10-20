"""Métriques du moteur de remédiation (préfixe ra_)."""

from prometheus_client import Counter, Gauge, Histogram

ALERTS = Counter("ra_alerts_received_total", "Alertes reçues", ["source", "category", "deduplicated"])
INCIDENTS = Counter("ra_incidents_total", "Incidents clos ou escaladés", ["category", "outcome"])
REMEDIATION_DURATION = Histogram(
    "ra_remediation_duration_seconds",
    "Durée d'une tentative de remédiation (étapes + vérification)",
    ["playbook"],
    buckets=(1, 2, 5, 10, 20, 30, 60, 120, 300),
)
VERIFICATIONS = Counter("ra_verification_runs_total", "Vérifications synthétiques", ["status", "trigger"])
MTTR = Histogram(
    "ra_mttr_seconds",
    "Temps de rétablissement (ouverture -> clôture vérifiée)",
    buckets=(5, 10, 20, 30, 45, 60, 90, 120, 300, 600),
)
PHASE = Gauge("ra_system_phase", "Phase système courante (1 = active)", ["phase"])
SERVICE_HEALTH = Gauge("ra_service_health", "Santé observée (2 = UP, 1 = DEGRADED, 0 = DOWN/UNKNOWN)", ["service"])
QUEUE_DEPTH = Gauge("ra_orchestrator_queue_depth", "Incidents en attente de traitement")
