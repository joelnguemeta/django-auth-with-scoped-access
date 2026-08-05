from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from scoped_access import RoleService, engine
from scoped_access.models import Role, ScopeAssignment
from scoped_access.mutations import managed_assignment_mutation, managed_role_mutation
from tests.testapp.models import GlobalThing, Node

SCOPED_ACCESS_ORG = {
    "HIERARCHY": [
        {"level": "ORGANIZATION", "model": "testapp.Node", "discriminator": {"level": "ORGANIZATION"}}
    ],
    "ROLE_OWNER_LEVELS": ["ORGANIZATION"],
}


@pytest.fixture
def orphan_world(settings, db):
    settings.SCOPED_ACCESS = SCOPED_ACCESS_ORG
    users = get_user_model()
    bootstrap = users.objects.create(username="root", is_superuser=True)
    user = users.objects.create(username="member")
    owner = Node.objects.create(slug="owner", level="ORGANIZATION")
    other = Node.objects.create(slug="other", level="ORGANIZATION")
    global_thing = GlobalThing.objects.create(slug="global")

    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    view = Permission.objects.create(content_type=ct, codename="view_thing", name="Can view thing")
    system_role = RoleService.create(by=bootstrap, name="viewer")
    system_role.grant_permissions(view, by=bootstrap)
    assignment = ScopeAssignment.objects.grant(user=user, role=system_role, scope=owner, by=bootstrap)
    custom_role = RoleService.create(by=bootstrap, name="custom", owner=owner)

    return {
        "bootstrap": bootstrap,
        "user": user,
        "owner": owner,
        "other": other,
        "global_thing": global_thing,
        "view": view,
        "assignment": assignment,
        "custom_role": custom_role,
    }


def test_orphan_assignment_contributes_no_access(orphan_world):
    user = orphan_world["user"]
    permission = "things.view_thing"
    assert engine.has_perm(user, permission, orphan_world["global_thing"])

    orphan_world["owner"].delete()
    assignment = ScopeAssignment.objects.get(pk=orphan_world["assignment"].pk)

    assert assignment.scope is None
    assert not engine.covers(assignment, orphan_world["global_thing"])
    assert engine.user_permissions(user) == set()
    assert not engine.has_perm(user, permission, orphan_world["global_thing"])
    assert not engine.accessible_nodes(user, "ORGANIZATION").exists()
    assert engine.access_summary(user) == {"permissions": [], "assignments": []}


def test_orphan_role_owner_denies_visibility_and_management(orphan_world):
    role = orphan_world["custom_role"]
    orphan_world["owner"].delete()
    role.refresh_from_db()

    assert role.owner_id is not None
    assert role.owner is None
    assert not engine.role_visible(orphan_world["bootstrap"], role)
    assert not engine.role_assignable(role, "ORGANIZATION", orphan_world["other"])
    assert not engine.can_manage_role(orphan_world["bootstrap"], role)
    assert not engine.can_grant_permission(orphan_world["bootstrap"], role, "things.view_thing")


def test_assignment_with_orphan_role_owner_contributes_no_access(orphan_world):
    users = get_user_model()
    user = users.objects.create(username="custom-role-member")
    role = orphan_world["custom_role"]
    role.grant_permissions(orphan_world["view"], by=orphan_world["bootstrap"])
    assignment = ScopeAssignment.objects.grant(
        user=user,
        role=role,
        scope=orphan_world["owner"],
        by=orphan_world["bootstrap"],
    )
    permission = "things.view_thing"
    assert engine.has_perm(user, permission, orphan_world["owner"])

    with managed_role_mutation():
        Role.objects.filter(pk=role.pk).update(owner_id="missing-owner")
    assignment = ScopeAssignment.objects.get(pk=assignment.pk)

    assert not engine.covers(assignment, orphan_world["owner"])
    assert engine.user_permissions(user) == set()
    assert engine.access_summary(user) == {"permissions": [], "assignments": []}


def test_malformed_assignment_without_content_type_fails_closed(orphan_world):
    role = RoleService.create(by=orphan_world["bootstrap"], name="malformed-role")
    with managed_assignment_mutation():
        malformed = ScopeAssignment.objects.create(
            user=orphan_world["bootstrap"],
            role=role,
            level="ORGANIZATION",
            scope_id="missing",
        )

    assert not engine.covers(malformed, orphan_world["global_thing"])


def test_malformed_assignment_scope_id_fails_closed(orphan_world):
    role = RoleService.create(by=orphan_world["bootstrap"], name="malformed-scope-role")
    scope_ct = ContentType.objects.get_for_model(Node)
    with managed_assignment_mutation():
        malformed = ScopeAssignment.objects.create(
            user=orphan_world["bootstrap"],
            role=role,
            level="ORGANIZATION",
            scope_ct=scope_ct,
            scope_id="not-a-number",
        )

    assert not engine.covers(malformed, orphan_world["global_thing"])


@pytest.mark.parametrize(
    ("level", "with_scope"),
    [("MISSING", True), ("ORGANIZATION", False)],
    ids=["unknown-level", "modeled-level-without-scope"],
)
def test_malformed_assignment_level_scope_shape_fails_closed(orphan_world, level, with_scope):
    users = get_user_model()
    user = users.objects.create(username=f"malformed-{level.lower()}-{with_scope}")
    role = RoleService.create(by=orphan_world["bootstrap"], name=f"malformed-{level}-{with_scope}")
    role.grant_permissions(orphan_world["view"], by=orphan_world["bootstrap"])
    fields = {"scope": orphan_world["owner"]} if with_scope else {}
    with managed_assignment_mutation():
        malformed = ScopeAssignment.objects.create(user=user, role=role, level=level, **fields)

    assert not engine.covers(malformed, orphan_world["global_thing"])
    assert engine.user_permissions(user) == set()
