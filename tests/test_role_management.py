from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from scoped_access import RoleService
from scoped_access.exceptions import (
    AssignmentManagementPermissionError,
    DirectRolePermissionMutationError,
    RoleAssignmentError,
    RoleManagementPermissionError,
    RoleOwnershipError,
)
from scoped_access.models import Role, ScopeAssignment
from tests.testapp.models import Node

SCOPED_ACCESS_ORG = {
    "HIERARCHY": [
        {"level": "ORGANIZATION", "model": "testapp.Node", "discriminator": {"level": "ORGANIZATION"}}
    ],
    "ROLE_OWNER_LEVELS": ["ORGANIZATION"],
    "GRANTABLE_PERMISSIONS": "self",
}


@pytest.fixture
def role_world(settings, db):
    settings.SCOPED_ACCESS = SCOPED_ACCESS_ORG
    users = get_user_model()
    bootstrap = users.objects.create(username="root", is_superuser=True)
    manager = users.objects.create(username="manager")
    outsider = users.objects.create(username="outsider")
    org_a = Node.objects.create(slug="org-a", level="ORGANIZATION")
    org_b = Node.objects.create(slug="org-b", level="ORGANIZATION")

    manage_roles = Permission.objects.get(content_type__app_label="scoped_access", codename="manage_roles")
    manage_assignments = Permission.objects.get(
        content_type__app_label="scoped_access", codename="manage_assignments"
    )
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    view = Permission.objects.create(content_type=ct, codename="view_thing", name="Can view thing")
    delete = Permission.objects.create(content_type=ct, codename="delete_thing", name="Can delete thing")

    manager_role = Role.objects.create(name="organization role manager")
    manager_role.grant_permissions(manage_roles, manage_assignments, view, by=bootstrap)
    ScopeAssignment.objects.grant(user=manager, role=manager_role, scope=org_a, by=bootstrap)

    return {
        "bootstrap": bootstrap,
        "manager": manager,
        "outsider": outsider,
        "org_a": org_a,
        "org_b": org_b,
        "view": view,
        "delete": delete,
    }


def test_role_service_enforces_r4_for_creation_and_deletion(role_world):
    role = RoleService.create(
        by=role_world["manager"],
        name="triage",
        owner=role_world["org_a"],
        permissions=[role_world["view"]],
    )
    assert role.owner_level == "ORGANIZATION"

    with pytest.raises(RoleManagementPermissionError):
        RoleService.create(by=role_world["manager"], name="global-admin")
    with pytest.raises(RoleManagementPermissionError):
        RoleService.create(by=role_world["manager"], name="foreign", owner=role_world["org_b"])
    with pytest.raises(RoleManagementPermissionError):
        RoleService.update(role, by=role_world["manager"], owner=role_world["org_b"])
    assert role.owner == role_world["org_a"]
    with pytest.raises(RoleManagementPermissionError):
        RoleService.delete(role, by=role_world["outsider"])

    RoleService.delete(role, by=role_world["manager"])
    assert not Role.objects.filter(pk=role.pk).exists()


def test_permission_changes_enforce_r4_and_r5(role_world):
    role = RoleService.create(by=role_world["bootstrap"], name="triage", owner=role_world["org_a"])

    role.grant_permissions(role_world["view"], by=role_world["manager"])
    assert role.permissions.filter(pk=role_world["view"].pk).exists()

    with pytest.raises(RoleManagementPermissionError):
        role.grant_permissions(role_world["delete"], by=role_world["manager"])
    with pytest.raises(RoleManagementPermissionError):
        role.revoke_permissions(role_world["view"], by=role_world["outsider"])


def test_direct_permission_m2m_mutations_are_rejected(role_world):
    role = RoleService.create(by=role_world["bootstrap"], name="triage", owner=role_world["org_a"])

    with pytest.raises(DirectRolePermissionMutationError):
        role.permissions.add(role_world["view"])
    with pytest.raises(DirectRolePermissionMutationError):
        role.permissions.clear()


def test_custom_role_assignment_is_limited_to_owner_subtree(role_world):
    role = RoleService.create(by=role_world["bootstrap"], name="triage", owner=role_world["org_a"])

    assignment = ScopeAssignment.objects.grant(
        user=role_world["outsider"], role=role, scope=role_world["org_a"], by=role_world["manager"]
    )
    assert assignment.scope == role_world["org_a"]

    with pytest.raises(RoleAssignmentError):
        ScopeAssignment.objects.grant(
            user=role_world["outsider"], role=role, scope=role_world["org_b"], by=role_world["manager"]
        )
    with pytest.raises(RoleAssignmentError):
        ScopeAssignment.objects.grant(user=role_world["outsider"], role=role, by=role_world["manager"])


def test_assignment_grant_requires_manage_assignments_at_target_scope(role_world):
    role = Role.objects.create(name="system-member")

    assignment = ScopeAssignment.objects.grant(
        user=role_world["outsider"], role=role, scope=role_world["org_a"], by=role_world["manager"]
    )
    assert assignment.scope == role_world["org_a"]

    with pytest.raises(AssignmentManagementPermissionError):
        ScopeAssignment.objects.grant(
            user=role_world["outsider"], role=role, scope=role_world["org_b"], by=role_world["manager"]
        )
    with pytest.raises(AssignmentManagementPermissionError):
        ScopeAssignment.objects.grant(user=role_world["outsider"], role=role, by=role_world["manager"])


def test_role_owner_level_must_be_allowed(role_world, settings):
    settings.SCOPED_ACCESS = {**SCOPED_ACCESS_ORG, "ROLE_OWNER_LEVELS": []}

    with pytest.raises(RoleOwnershipError):
        Role.objects.create(name="invalid", owner=role_world["org_a"])
