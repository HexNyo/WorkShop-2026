"""Modèle déclaratif des playbooks et résolution des gabarits {{incident.*}}."""

from __future__ import annotations

import re
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, ValidationError

_TEMPLATE = re.compile(r"\{\{\s*([a-z_.]+)\s*\}\}")


class StepSpec(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    action: str = Field(pattern=r"^[a-z]+\.[a-z_]+$")
    target: str | None = Field(None, max_length=128)
    params: dict[str, Any] = Field(default_factory=dict)
    optional: bool = False


class PlaybookSpec(BaseModel):
    model_config = ConfigDict(frozen=True)

    code: str
    version: int
    category: str
    title: str
    steps: tuple[StepSpec, ...]
    post_verification_steps: tuple[StepSpec, ...]
    max_attempts: int
    step_timeout_seconds: int
    cooldown_seconds: int
    enabled: bool


class InvalidPlaybook(ValueError):
    pass


def parse_playbook(row: dict[str, Any], known_actions: frozenset[str]) -> PlaybookSpec:
    try:
        spec = PlaybookSpec(
            code=row["code"],
            version=row["version"],
            category=row["category"],
            title=row["title"],
            steps=tuple(StepSpec.model_validate(step) for step in row["steps"]),
            post_verification_steps=tuple(StepSpec.model_validate(step) for step in row["post_verification_steps"]),
            max_attempts=row["max_attempts"],
            step_timeout_seconds=row["step_timeout_seconds"],
            cooldown_seconds=row["cooldown_seconds"],
            enabled=row["enabled"],
        )
    except (ValidationError, KeyError, TypeError) as exc:
        raise InvalidPlaybook(f"playbook {row.get('code')}: {exc}") from exc
    unknown = {step.action for step in spec.steps + spec.post_verification_steps} - known_actions
    if unknown:
        raise InvalidPlaybook(f"playbook {spec.code}: unknown action(s) {sorted(unknown)}")
    return spec


class UnresolvedTemplate(LookupError):
    pass


def render(value: Any, context: dict[str, str | None]) -> Any:
    """Résout récursivement les gabarits ; une variable absente ou vide est une erreur."""
    if isinstance(value, str):
        def substitute(match: re.Match[str]) -> str:
            resolved = context.get(match.group(1))
            if not resolved:
                raise UnresolvedTemplate(match.group(1))
            return resolved

        return _TEMPLATE.sub(substitute, value)
    if isinstance(value, dict):
        return {key: render(item, context) for key, item in value.items()}
    if isinstance(value, list):
        return [render(item, context) for item in value]
    return value
