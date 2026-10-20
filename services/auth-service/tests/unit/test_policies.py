from __future__ import annotations

import pytest

from app.domain.errors import PolicyViolation
from app.domain.models import PrincipalKind
from app.domain.policies import check_containment_allowed, service_audiences, service_roles_for
from app.services.bootstrap import bootstrap_variable

REMEDIATION_SUB = "00000000-0000-4000-8000-000000000101"
ADMIN_SUB = "00000000-0000-4000-8000-000000000001"


def test_service_audiences_follow_roles() -> None:
    assert service_audiences(["svc.synthetic"]) == {"payment-api"}
    assert service_audiences(["svc.remediation", "svc.resource_server"]) == {"payment-api", "auth-service"}
    assert service_audiences(["svc.detector"]) == {"remediation-control"}
    assert service_audiences(["payment.customer"]) == frozenset()


def test_token_roles_are_scoped_to_requested_audience() -> None:
    roles = ("svc.remediation", "svc.resource_server")
    assert service_roles_for(roles, ["payment-api"]) == ("svc.remediation",)
    assert service_roles_for(roles, ["auth-service"]) == ("svc.remediation", "svc.resource_server")


def test_remediation_can_contain_regular_user(principal_factory) -> None:
    check_containment_allowed(
        actor_sub=REMEDIATION_SUB, actor_roles=["svc.remediation"], target=principal_factory(), disable=True
    )


@pytest.mark.parametrize(
    ("kind", "privileged", "message"),
    [
        (PrincipalKind.SERVICE, False, "service principals"),
        (PrincipalKind.USER, True, "privileged principal"),
    ],
)
def test_remediation_cannot_neutralise_platform(principal_factory, kind, privileged, message) -> None:
    target = principal_factory(kind=kind, privileged=privileged)
    with pytest.raises(PolicyViolation, match=message):
        check_containment_allowed(actor_sub=REMEDIATION_SUB, actor_roles=["svc.remediation"], target=target, disable=True)


def test_admin_can_contain_anyone_but_itself(principal_factory) -> None:
    service = principal_factory(kind=PrincipalKind.SERVICE)
    check_containment_allowed(actor_sub=ADMIN_SUB, actor_roles=["auth.admin"], target=service, disable=True)
    myself = principal_factory(principal_id=ADMIN_SUB, privileged=True)
    with pytest.raises(PolicyViolation, match="itself"):
        check_containment_allowed(actor_sub=ADMIN_SUB, actor_roles=["auth.admin"], target=myself, disable=True)


def test_other_roles_cannot_contain(principal_factory) -> None:
    with pytest.raises(PolicyViolation):
        check_containment_allowed(
            actor_sub=REMEDIATION_SUB, actor_roles=["noc.viewer"], target=principal_factory(), disable=False
        )


def test_bootstrap_variable_naming() -> None:
    assert bootstrap_variable("svc-remediation") == "AUTH_BOOTSTRAP_SVC_REMEDIATION_SECRET"
    assert bootstrap_variable("noc-operator") == "AUTH_BOOTSTRAP_NOC_OPERATOR_SECRET"
    assert bootstrap_variable("alice") == "AUTH_BOOTSTRAP_ALICE_SECRET"
