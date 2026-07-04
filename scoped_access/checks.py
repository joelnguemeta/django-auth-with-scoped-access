"""Startup validation of SCOPED_ACCESS (SPEC §3) via Django system checks."""

from __future__ import annotations

from django.conf import settings
from django.core import checks


@checks.register(checks.Tags.compatibility)
def check_scoped_access_config(app_configs, **kwargs):
    errors = []
    raw = getattr(settings, "SCOPED_ACCESS", {})
    entries = [
        {"level": e} if isinstance(e, str) else e for e in raw.get("HIERARCHY", [])
    ]

    names = [e.get("level") for e in entries]
    if len(names) != len(set(names)):
        errors.append(checks.Error("SCOPED_ACCESS: duplicate level names.", id="scoped_access.E001"))

    roots = [i for i, e in enumerate(entries) if not e.get("model")]
    if roots and roots != [0]:
        errors.append(
            checks.Error(
                "SCOPED_ACCESS: at most one root level (no model), and it must be first.",
                id="scoped_access.E002",
            )
        )

    modeled = [e for e in entries if e.get("model")]
    for e in modeled[1:]:
        if not e.get("parent"):
            errors.append(
                checks.Error(
                    f"SCOPED_ACCESS: level '{e.get('level')}' needs a 'parent' accessor "
                    "(every modeled level except the first must reach its parent).",
                    id="scoped_access.E003",
                )
            )

    modeled_names = {e["level"] for e in modeled}
    for owner_level in raw.get("ROLE_OWNER_LEVELS", []):
        if owner_level not in modeled_names:
            errors.append(
                checks.Error(
                    f"SCOPED_ACCESS: ROLE_OWNER_LEVELS entry '{owner_level}' is not a modeled level.",
                    id="scoped_access.E004",
                )
            )

    grantable = raw.get("GRANTABLE_PERMISSIONS", "self")
    if grantable not in ("self", "any") and not isinstance(grantable, (list, tuple, set)):
        errors.append(
            checks.Error(
                "SCOPED_ACCESS: GRANTABLE_PERMISSIONS must be 'self', 'any' or an explicit list.",
                id="scoped_access.E005",
            )
        )
    return errors
