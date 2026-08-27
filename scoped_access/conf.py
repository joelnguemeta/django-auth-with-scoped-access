"""SCOPED_ACCESS settings parsing (SPEC §3).

The hierarchy is configuration, not schema: hosts declare an ordered list
of levels, each mapping to one of their own models.

    SCOPED_ACCESS = {
        "HIERARCHY": [
            {"level": "NATIONAL"},                       # root: no model
            {"level": "REGIONAL", "model": "geography.Region"},
            {"level": "DISTRICT", "model": "geography.District", "parent": "region"},
        ],
        "ROLE_OWNER_LEVELS": ["FACILITY"],
        "GRANTABLE_PERMISSIONS": "self",
    }

`parent` is the ORM accessor from a level's model to the instance of the
previous *modeled* level. `discriminator` (optional) is a filter dict
selecting a level's rows when several levels share one model.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from django.conf import settings

from .exceptions import ScopedAccessConfigError
from .registry import Hierarchy, Level

DEFAULTS = {
    "HIERARCHY": [],
    "ROLE_OWNER_LEVELS": [],
    "GRANTABLE_PERMISSIONS": "self",
    "STRICT_REGISTRATION": False,
    "REAUTH": {"ENABLED": False, "TTL": 300},
}

# Swappable models, à la AUTH_USER_MODEL. Top-level settings (not keys of the
# SCOPED_ACCESS dict) because Django's swappable machinery resolves them by
# settings name. Must be set before the first migrate.
ROLE_MODEL_SETTING = "SCOPED_ACCESS_ROLE_MODEL"
ASSIGNMENT_MODEL_SETTING = "SCOPED_ACCESS_ASSIGNMENT_MODEL"


def ensure_swappable_defaults() -> None:
    """Django resolves Meta.swappable with getattr(settings, name): the
    setting must exist even when the host never swaps. Called at model
    import time.
    """
    for name, default in (
        (ROLE_MODEL_SETTING, "scoped_access.Role"),
        (ASSIGNMENT_MODEL_SETTING, "scoped_access.ScopeAssignment"),
    ):
        if not hasattr(settings, name):
            setattr(settings, name, default)


def role_model_label() -> str:
    return getattr(settings, ROLE_MODEL_SETTING, "scoped_access.Role")


def assignment_model_label() -> str:
    return getattr(settings, ASSIGNMENT_MODEL_SETTING, "scoped_access.ScopeAssignment")


def get_role_model():
    from django.apps import apps

    return apps.get_model(role_model_label())


def get_assignment_model():
    from django.apps import apps

    return apps.get_model(assignment_model_label())


@dataclass(frozen=True)
class ScopedAccessConfig:
    hierarchy: Hierarchy
    role_owner_levels: tuple[str, ...]
    grantable_permissions: object  # "self" | "any" | explicit list
    strict_registration: bool = False
    reauth: dict = field(default_factory=dict)


def _build_hierarchy(entries: list) -> Hierarchy:
    levels = []
    for entry in entries:
        if isinstance(entry, str):
            entry = {"level": entry}
        try:
            name = entry["level"]
        except KeyError as exc:
            raise ScopedAccessConfigError("Each HIERARCHY entry needs a 'level' key.") from exc
        levels.append(
            Level(
                name=name,
                model_label=entry.get("model"),
                parent=entry.get("parent"),
                discriminator=tuple(sorted((entry.get("discriminator") or {}).items())),
            )
        )
    return Hierarchy(tuple(levels))


def get_config() -> ScopedAccessConfig:
    """Parse settings on every call — cheap, and always in sync with
    `override_settings` in tests. Runtime caching (config is immutable at
    runtime, SPEC §11) is a later optimization.
    """
    raw = {**DEFAULTS, **getattr(settings, "SCOPED_ACCESS", {})}
    return ScopedAccessConfig(
        hierarchy=_build_hierarchy(raw["HIERARCHY"]),
        role_owner_levels=tuple(raw["ROLE_OWNER_LEVELS"]),
        grantable_permissions=raw["GRANTABLE_PERMISSIONS"],
        strict_registration=raw["STRICT_REGISTRATION"],
        reauth={**DEFAULTS["REAUTH"], **raw.get("REAUTH", {})},
    )
