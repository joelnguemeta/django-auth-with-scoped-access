"""Startup validation of SCOPED_ACCESS (SPEC §3) via Django system checks."""

from __future__ import annotations

from django.apps import apps
from django.conf import settings
from django.core import checks
from django.core.exceptions import FieldDoesNotExist


def _walk_relation_path(model, path: str) -> tuple[str | None, object | None]:
    """Follows a `__`-separated relation path from `model`.

    Returns (bad_part, final_model): `bad_part` is the first segment that is
    missing or non-relational (None when the whole path is valid), and
    `final_model` is the model the path lands on (None on failure).
    """
    current = model
    for part in path.split("__"):
        try:
            field = current._meta.get_field(part)
        except FieldDoesNotExist:
            return part, None
        current = field.related_model
        if current is None:
            return part, None
    return None, current


@checks.register(checks.Tags.compatibility)
def check_scoped_access_config(app_configs, **kwargs):
    errors = []
    raw = getattr(settings, "SCOPED_ACCESS", {})
    entries = [{"level": e} if isinstance(e, str) else e for e in raw.get("HIERARCHY", [])]

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
    for i, e in enumerate(modeled):
        model_label = e.get("model")
        try:
            model_class = apps.get_model(model_label)
        except (LookupError, ValueError):
            errors.append(
                checks.Error(
                    f"SCOPED_ACCESS: model '{model_label}' for level '{e.get('level')}' could not be loaded.",
                    id="scoped_access.E006",
                )
            )
            continue

        parent = e.get("parent")
        if i > 0 and not parent:
            errors.append(
                checks.Error(
                    f"SCOPED_ACCESS: level '{e.get('level')}' needs a 'parent' accessor "
                    "(every modeled level except the first must reach its parent).",
                    id="scoped_access.E003",
                )
            )

        if parent:
            # Multi-hop accessors ("unit__facility") are legal: the engine
            # walks them with _follow() and joins them in ORM lookups.
            bad_part, _final = _walk_relation_path(model_class, parent)
            if bad_part is not None:
                errors.append(
                    checks.Error(
                        f"SCOPED_ACCESS: parent accessor '{parent}' on model '{model_label}' "
                        f"is invalid at segment '{bad_part}'.",
                        id="scoped_access.E007",
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

    from .registry import resources

    for model, anchor in resources.items():
        bad_part, _final = _walk_relation_path(model, anchor)
        if bad_part is not None:
            errors.append(
                checks.Error(
                    f"SCOPED_ACCESS: anchor '{anchor}' for model '{model._meta.label}' "
                    f"is invalid at segment '{bad_part}'.",
                    id="scoped_access.E008",
                )
            )

    return errors
