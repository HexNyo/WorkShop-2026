"""Règles d'autorisation de l'émetteur : audiences, rôles, garde de confinement."""

from __future__ import annotations

from collections.abc import Iterable, Mapping

from app.domain.errors import PolicyViolation
from app.domain.models import Principal, PrincipalKind

# Rôles
ROLE_AUTH_ADMIN = "auth.admin"
ROLE_NOC_VIEWER = "noc.viewer"
ROLE_SVC_REMEDIATION = "svc.remediation"
ROLE_SVC_RESOURCE_SERVER = "svc.resource_server"

# Audiences
AUDIENCE_SELF = "auth-service"

# Un jeton humain est utilisable sur toute la surface exposée par la passerelle.
USER_AUDIENCES: tuple[str, ...] = ("auth-service", "payment-api", "remediation-supervision", "assistant")

# Un jeton de service n'ouvre que les audiences justifiées par ses rôles.
SERVICE_ROLE_AUDIENCES: Mapping[str, frozenset[str]] = {
    "svc.remediation": frozenset({"payment-api", "auth-service"}),
    "svc.synthetic": frozenset({"payment-api"}),
    "svc.detector": frozenset({"remediation-control"}),
    "svc.resource_server": frozenset({"auth-service"}),
}


def service_audiences(roles: Iterable[str]) -> frozenset[str]:
    allowed: set[str] = set()
    for role in roles:
        allowed |= SERVICE_ROLE_AUDIENCES.get(role, frozenset())
    return frozenset(allowed)


def service_roles_for(roles: Iterable[str], audiences: Iterable[str]) -> tuple[str, ...]:
    """Ne conserve dans le jeton que les rôles utiles aux audiences demandées."""
    wanted = set(audiences)
    return tuple(sorted(role for role in roles if SERVICE_ROLE_AUDIENCES.get(role, frozenset()) & wanted))


def check_containment_allowed(*, actor_sub: str, actor_roles: Iterable[str], target: Principal, disable: bool) -> None:
    """Empêche un moteur de remédiation (ou un détecteur compromis) de neutraliser
    l'administration ou les comptes de service de la plateforme."""
    roles = set(actor_roles)
    if str(target.id) == actor_sub:
        raise PolicyViolation("a principal cannot contain itself")
    if ROLE_AUTH_ADMIN in roles:
        return
    if ROLE_SVC_REMEDIATION not in roles:
        raise PolicyViolation("containment requires svc.remediation or auth.admin")
    if target.kind is PrincipalKind.SERVICE:
        raise PolicyViolation("automated containment of service principals is not allowed")
    if target.is_privileged:
        action = "disable" if disable else "revoke tokens of"
        raise PolicyViolation(f"automated remediation may not {action} a privileged principal")
