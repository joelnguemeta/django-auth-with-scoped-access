"""Authorization engine (SPEC §4–§6) — framework-agnostic core.

No DRF dependency here (doctrine): the DRF glue lives in `scoped_access.drf`.
All temporal functions accept `at` (default: now) so effectiveness is
evaluated at read time (SPEC §8.2).
"""

from __future__ import annotations

from django.contrib.contenttypes.models import ContentType
from django.db.models import Q

from . import cache
from .conf import get_assignment_model, get_config
from .registry import resources

# Anchor resolution outcomes (SPEC §4.1)
NODE = "node"
GLOBAL = "global"  # unregistered model: skips the scope check only
DENIED = "denied"  # registered but null anchor: only root scopes cover it


# ─────────────────────────────────────────────────────────────────────────────
# Scope resolution (SPEC §4)
# ─────────────────────────────────────────────────────────────────────────────


def _follow(obj, path: str):
    for part in path.split("__"):
        obj = getattr(obj, part, None)
        if obj is None:
            return None
    return obj


def resolve_anchor(obj) -> tuple[str, object | None]:
    """Returns (kind, node) with kind in {NODE, GLOBAL, DENIED}."""
    cfg = get_config()
    model = type(obj)
    if cfg.hierarchy.is_node_model(model):
        return NODE, obj
    path = resources.anchor_for(model)
    if path is None:
        return GLOBAL, None
    node = _follow(obj, path)
    return (NODE, node) if node is not None else (DENIED, None)


def iter_ancestors(node):
    """Yields the node then its ancestors, walking declared parent accessors."""
    cfg = get_config()
    while node is not None:
        yield node
        accessor = cfg.hierarchy.parent_accessor_for_model(type(node))
        node = getattr(node, accessor) if accessor else None


def _same_node(assignment, node) -> bool:
    return str(node.pk) == str(assignment.scope_id) and (
        ContentType.objects.get_for_model(type(node)).pk == assignment.scope_ct_id
    )


def covers(assignment, obj) -> bool:
    """SPEC §4.2 — inclusive downward, never upward."""
    if assignment.is_root_scope:
        return True
    kind, node = resolve_anchor(obj)
    if kind == GLOBAL:
        return True
    if node is None:
        return False
    return any(_same_node(assignment, ancestor) for ancestor in iter_ancestors(node))


# ─────────────────────────────────────────────────────────────────────────────
# Permission decision (SPEC §5)
# ─────────────────────────────────────────────────────────────────────────────


def _fetch_effective(user, at=None):
    return (
        get_assignment_model()
        .objects.filter(user=user)
        .effective(at)
        .select_related("role")
        .prefetch_related("role__permissions__content_type")
    )


def effective_assignments(user, at=None):
    """Effective assignments, memoized per request when the store is active
    (SPEC §11). Explicit-clock calls bypass the cache — only "now" answers
    may be reused within a request.
    """
    if at is not None:
        return _fetch_effective(user, at)
    store = cache.get_store()
    if store is None:
        return _fetch_effective(user)
    key = ("assignments", str(user.pk))
    if key not in store:
        store[key] = list(_fetch_effective(user))
    return store[key]


def _role_perms(role) -> set[str]:
    return {f"{p.content_type.app_label}.{p.codename}" for p in role.permissions.all()}


def user_permissions(user, obj=None, at=None) -> set[str]:
    """Effective permissions, optionally restricted to those covering `obj`."""
    if not user.is_active:
        return set()
    kind, node = (GLOBAL, None) if obj is None else resolve_anchor(obj)
    perms: set[str] = set()
    for assignment in effective_assignments(user, at):
        if kind == GLOBAL:
            covered = True
        elif kind == DENIED:
            covered = assignment.is_root_scope
        else:
            covered = assignment.is_root_scope or (
                node is not None
                and any(_same_node(assignment, anc) for anc in iter_ancestors(node))
            )
        if covered:
            perms |= _role_perms(assignment.role)
    return perms


def has_perm(user, perm: str, obj=None, at=None) -> bool:
    if not user.is_active:  # checked BEFORE superuser (SPEC §5)
        return False
    if user.is_superuser:
        return True
    return perm in user_permissions(user, obj, at)


def user_covers(user, obj, at=None) -> bool:
    """Scope-only admission (SPEC §5 write guard): does any effective
    assignment cover `obj`? Use in create/update paths, where the object may
    not be persisted yet — the RBAC check (`has_perm`) applies separately.
    """
    if not user.is_active:
        return False
    if user.is_superuser:
        return True
    kind, node = resolve_anchor(obj)
    if kind == GLOBAL:
        return True
    for assignment in effective_assignments(user, at):
        if assignment.is_root_scope:
            return True
        if kind == NODE and node is not None and any(
            _same_node(assignment, anc) for anc in iter_ancestors(node)
        ):
            return True
    return False


def access_summary(user, at=None) -> dict:
    """Engine-level content of GET /me/access/ (SPEC §10): effective
    assignments only, plus the union of their permissions.
    """
    assignments = []
    perms: set[str] = set()
    if user.is_active:
        for a in effective_assignments(user, at):
            role_perms = sorted(_role_perms(a.role))
            perms.update(role_perms)
            assignments.append(
                {
                    "role": a.role,
                    "level": a.level,
                    "scope": a.scope if a.scope_id else None,
                    "status": a.status,
                    "valid_until": a.valid_until,
                    "permissions": role_perms,
                }
            )
    return {"permissions": sorted(perms), "assignments": assignments}


# ─────────────────────────────────────────────────────────────────────────────
# Collection filtering (SPEC §4.3) — database-level, never per-row
# ─────────────────────────────────────────────────────────────────────────────


def _up_path(hierarchy, from_rank: int, to_rank: int) -> str:
    """ORM path climbing from level rank `from_rank` up to `to_rank`."""
    return "__".join(hierarchy.levels[r].parent for r in range(from_rank, to_rank, -1))


def accessible_nodes(user, level_name: str, at=None):
    """QuerySet of nodes at `level_name` the user's assignments reach."""
    cfg = get_config()
    level = cfg.hierarchy.level(level_name)
    qs = level.queryset()
    if user.is_superuser:
        return qs

    target_rank = cfg.hierarchy.rank(level_name)
    q = Q(pk__in=[])
    for a in effective_assignments(user, at):
        if a.is_root_scope:
            return qs
        a_rank = cfg.hierarchy.rank(a.level)
        if a_rank > target_rank:
            continue  # deeper assignments contribute nothing (no upward coverage)
        if a_rank == target_rank:
            q |= Q(pk=a.scope_id)
        else:
            q |= Q(**{f"{_up_path(cfg.hierarchy, target_rank, a_rank)}__pk": a.scope_id})
    return qs.filter(q).distinct()


def _anchor_target_levels(model):
    """Possible hierarchy levels of a model's anchor (introspected once)."""
    cfg = get_config()
    path = resources.anchor_for(model)
    current = model
    for part in path.split("__"):
        current = current._meta.get_field(part).related_model
    return [(cfg.hierarchy.rank(lvl.name), lvl) for lvl in cfg.hierarchy.levels_for_model(current)]


def scope_filter_q(user, model, at=None) -> Q:
    """Q filter restricting a registered resource model to the user's scope."""
    if user.is_superuser:
        return Q()
    anchor = resources.anchor_for(model)
    if anchor is None:
        return Q()  # global resources are unrestricted (RBAC still applies)

    cfg = get_config()
    target_levels = _anchor_target_levels(model)
    q = Q(pk__in=[])
    for a in effective_assignments(user, at):
        if a.is_root_scope:
            return Q()
        a_rank = cfg.hierarchy.rank(a.level)
        for rank, _level in target_levels:
            if rank < a_rank:
                continue
            up = _up_path(cfg.hierarchy, rank, a_rank)
            path = f"{anchor}__{up}" if up else anchor
            q |= Q(**{f"{path}__pk": a.scope_id})
    return q


def visible_resources(user, model, at=None):
    return model._default_manager.filter(scope_filter_q(user, model, at)).distinct()


# ─────────────────────────────────────────────────────────────────────────────
# Roles & ownership (SPEC §6)
# ─────────────────────────────────────────────────────────────────────────────


def role_visible(user, role, at=None) -> bool:
    """R1 — system roles everywhere; custom roles inside a covering scope."""
    if role.owner_id is None or user.is_superuser:
        return True
    owner = role.owner
    return any(covers(a, owner) for a in effective_assignments(user, at))


def role_assignable(role, level_name: str | None, node) -> bool:
    """R2 — custom roles only in the owner's subtree, never at root."""
    if role.owner_id is None:
        return True
    cfg = get_config()
    if node is None or level_name is None or cfg.hierarchy.is_root(level_name):
        return False
    owner_ct = role.owner_ct_id
    return any(
        str(anc.pk) == str(role.owner_id)
        and ContentType.objects.get_for_model(type(anc)).pk == owner_ct
        for anc in iter_ancestors(node)
    )


def can_grant_permission(actor, role, perm: str, at=None) -> bool:
    """R5 — anti-escalation: only delegate what you hold at the owner scope."""
    if actor.is_superuser:
        return True
    policy = get_config().grantable_permissions
    if policy == "any":
        return True
    if isinstance(policy, (list, tuple, set)):
        return perm in policy

    # policy == "self"
    if role.owner_id is None:
        held = set()
        for a in effective_assignments(actor, at):
            if a.is_root_scope:
                held |= _role_perms(a.role)
        return perm in held
    return perm in user_permissions(actor, role.owner, at)
