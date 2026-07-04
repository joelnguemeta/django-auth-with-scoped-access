"""Conformance adapter (SPEC §12) for the Django reference implementation.

Loads each `conformance/cases/*.json`, materializes it onto the generic
testapp models, freezes the clock at the case's `now`, and runs every check
against the engine's public API.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from scoped_access import engine
from scoped_access.models import Role, ScopeAssignment
from scoped_access.registry import resources
from tests.testapp.models import GlobalThing, Node, Resource

CASES_DIR = Path(__file__).resolve().parent.parent / "conformance" / "cases"
CASE_PATHS = sorted(CASES_DIR.glob("*.json"))


def _dt(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value.replace("Z", "+00:00")) if value else None


def _perm(label: str) -> Permission:
    """Materialize an opaque '<app>.<codename>' permission string."""
    app_label, codename = label.split(".", 1)
    ct, _ = ContentType.objects.get_or_create(app_label=app_label, model="conformanceobj")
    perm, _ = Permission.objects.get_or_create(
        content_type=ct, codename=codename, defaults={"name": label}
    )
    return perm


class Fixture:
    """A materialized conformance case."""

    def __init__(self, case: dict):
        self.now = _dt(case["now"])
        self.nodes: dict[str, Node] = {}
        self.roles: dict[str, Role] = {}
        self.users: dict[str, object] = {}
        self.resources: dict[str, object] = {}

        for spec in case["nodes"]:
            self.nodes[spec["id"]] = Node.objects.create(
                slug=spec["id"],
                level=spec["level"],
                parent=self.nodes[spec["parent"]] if spec.get("parent") else None,
            )

        for spec in case["roles"]:
            role = Role.objects.create(name=spec["id"])
            if spec.get("owner"):
                owner = self.nodes[spec["owner"]]
                role.owner_ct = ContentType.objects.get_for_model(Node)
                role.owner_id = str(owner.pk)
                role.owner_level = owner.level
                role.save()
            for label in spec["permissions"]:
                role.permissions.add(_perm(label))
            self.roles[spec["id"]] = role

        user_model = get_user_model()
        for spec in case["principals"]:
            user = user_model.objects.create(
                username=spec["id"],
                is_active=spec["active"],
                is_superuser=spec["superuser"],
            )
            self.users[spec["id"]] = user
            for a in spec["assignments"]:
                node = self.nodes[a["node"]] if a.get("node") else None
                ScopeAssignment.objects.create(
                    user=user,
                    role=self.roles[a["role"]],
                    level=a.get("level"),
                    scope_ct=ContentType.objects.get_for_model(Node) if node else None,
                    scope_id=str(node.pk) if node else None,
                    status=a["status"],
                    valid_from=_dt(a.get("valid_from")),
                    valid_until=_dt(a.get("valid_until")),
                )

        for spec in case["resources"]:
            if spec.get("anchor"):
                self.resources[spec["id"]] = Resource.objects.create(
                    slug=spec["id"], anchor=self.nodes[spec["anchor"]]
                )
            else:
                # Fixture "anchor: null" means *global*: an unregistered model.
                self.resources[spec["id"]] = GlobalThing.objects.create(slug=spec["id"])


def _run_check(fx: Fixture, chk: dict):
    """Returns the observed value, in the same shape as the check's `expect`."""
    kind = chk["type"]
    if kind == "perm":
        obj = fx.resources[chk["resource"]] if chk.get("resource") else None
        return engine.has_perm(fx.users[chk["principal"]], chk["permission"], obj, at=fx.now)
    if kind == "accessible_nodes":
        qs = engine.accessible_nodes(fx.users[chk["principal"]], chk["level"], at=fx.now)
        return sorted(qs.values_list("slug", flat=True))
    if kind == "resource_visible":
        obj = fx.resources[chk["resource"]]
        if isinstance(obj, GlobalThing):
            return True
        visible = engine.visible_resources(fx.users[chk["principal"]], Resource, at=fx.now)
        return visible.filter(pk=obj.pk).exists()
    if kind == "role_visible":
        return engine.role_visible(fx.users[chk["principal"]], fx.roles[chk["role"]], at=fx.now)
    if kind == "role_assignable":
        node = fx.nodes[chk["node"]] if chk.get("node") else None
        return engine.role_assignable(fx.roles[chk["role"]], chk.get("level"), node)
    if kind == "can_grant_permission":
        return engine.can_grant_permission(
            fx.users[chk["actor"]], fx.roles[chk["role"]], chk["permission"], at=fx.now
        )
    raise NotImplementedError(f"Unknown check type: {kind}")


@pytest.mark.django_db
@pytest.mark.parametrize("case_path", CASE_PATHS, ids=lambda p: p.stem)
def test_conformance(case_path: Path, settings):
    case = json.loads(case_path.read_text())
    cfg = case["config"]

    hierarchy, seen_modeled = [], False
    for name in cfg["hierarchy"]:
        if name == cfg.get("root_level"):
            hierarchy.append({"level": name})
        else:
            hierarchy.append(
                {
                    "level": name,
                    "model": "testapp.Node",
                    "parent": "parent" if seen_modeled else None,
                    "discriminator": {"level": name},
                }
            )
            seen_modeled = True
    settings.SCOPED_ACCESS = {
        "HIERARCHY": hierarchy,
        "ROLE_OWNER_LEVELS": cfg["role_owner_levels"],
        "GRANTABLE_PERMISSIONS": cfg["grantable_permissions"],
    }

    resources.clear()
    resources.register(Resource, anchor="anchor")

    fx = Fixture(case)
    failures = []
    for i, chk in enumerate(case["checks"]):
        got = _run_check(fx, chk)
        expect = sorted(chk["expect"]) if isinstance(chk["expect"], list) else chk["expect"]
        if got != expect:
            failures.append(f"  check[{i}] {chk} → got {got}")
    assert not failures, f"{case_path.name}: {len(failures)} check(s) failed:\n" + "\n".join(failures)
