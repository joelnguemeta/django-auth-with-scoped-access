from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from scoped_access import RoleService, engine
from scoped_access.cache import request_cache
from scoped_access.exceptions import (
    AssignmentManagementPermissionError,
    DirectAssignmentMutationError,
    DirectRoleMutationError,
    DirectRolePermissionMutationError,
    InvalidAssignmentTransitionError,
    RoleAssignmentError,
    RoleManagementPermissionError,
    RoleOwnershipError,
)
from scoped_access.models import Role, RolePermission, ScopeAssignment
from tests.testapp.models import Node

SCOPED_ACCESS_ORG = {
    "HIERARCHY": [{"level": "ORGANIZATION", "model": "testapp.Node", "discriminator": {"level": "ORGANIZATION"}}],
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
    manage_assignments = Permission.objects.get(content_type__app_label="scoped_access", codename="manage_assignments")
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    view = Permission.objects.create(content_type=ct, codename="view_thing", name="Can view thing")
    delete = Permission.objects.create(content_type=ct, codename="delete_thing", name="Can delete thing")

    manager_role = RoleService.create(by=bootstrap, name="organization role manager")
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


def test_existing_assignment_fails_closed_after_role_owner_moves(role_world):
    role = RoleService.create(by=role_world["bootstrap"], name="triage", owner=role_world["org_a"])
    role.grant_permissions(role_world["view"], by=role_world["bootstrap"])
    assignment = ScopeAssignment.objects.grant(
        user=role_world["outsider"],
        role=role,
        scope=role_world["org_a"],
        by=role_world["manager"],
    )
    permission = "things.view_thing"
    with request_cache():
        assert engine.has_perm(role_world["outsider"], permission, role_world["org_a"])

        RoleService.update(role, by=role_world["bootstrap"], owner=role_world["org_b"])

        assert not engine.covers(assignment, role_world["org_a"])
        assert not engine.has_perm(role_world["outsider"], permission, role_world["org_a"])
    assert engine.access_summary(role_world["outsider"]) == {"permissions": [], "assignments": []}


def test_assignment_grant_requires_manage_assignments_at_target_scope(role_world):
    role = RoleService.create(by=role_world["bootstrap"], name="system-member")

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


def test_assignment_manager_cannot_delegate_permissions_they_do_not_hold(role_world):
    dangerous_role = RoleService.create(
        by=role_world["bootstrap"],
        name="dangerous system role",
        permissions=[role_world["delete"]],
    )

    with pytest.raises(RoleAssignmentError, match="cannot delegate this role"):
        ScopeAssignment.objects.grant(
            user=role_world["manager"],
            role=dangerous_role,
            scope=role_world["org_a"],
            by=role_world["manager"],
        )

    assert not engine.has_perm(role_world["manager"], "things.delete_thing", role_world["org_a"])


def test_assignment_manager_can_delegate_permissions_they_hold_at_target(role_world):
    permitted_role = RoleService.create(
        by=role_world["bootstrap"],
        name="permitted system role",
        permissions=[role_world["view"]],
    )

    assignment = ScopeAssignment.objects.grant(
        user=role_world["outsider"],
        role=permitted_role,
        scope=role_world["org_a"],
        by=role_world["manager"],
    )

    assert assignment.role == permitted_role
    assert engine.has_perm(role_world["outsider"], "things.view_thing", role_world["org_a"])


def test_role_owner_level_must_be_allowed(role_world, settings):
    settings.SCOPED_ACCESS = {**SCOPED_ACCESS_ORG, "ROLE_OWNER_LEVELS": []}

    with pytest.raises(RoleOwnershipError):
        RoleService.create(by=role_world["bootstrap"], name="invalid", owner=role_world["org_a"])


def test_direct_security_sensitive_orm_mutations_are_rejected(role_world):
    with pytest.raises(DirectRoleMutationError):
        Role.objects.create(name="bypass")

    role = RoleService.create(by=role_world["bootstrap"], name="managed")
    role.name = "bypass"
    with pytest.raises(DirectRoleMutationError):
        role.save()
    with pytest.raises(DirectRoleMutationError):
        Role.objects.filter(pk=role.pk).update(name="bypass")
    with pytest.raises(DirectRoleMutationError):
        RolePermission.objects.create(role=role, permission=role_world["view"])

    with pytest.raises(DirectAssignmentMutationError):
        ScopeAssignment.objects.create(
            user=role_world["outsider"],
            role=role,
            level="ORGANIZATION",
            scope_id=str(role_world["org_a"].pk),
        )

    assignment = ScopeAssignment.objects.grant(
        user=role_world["outsider"], role=role, scope=role_world["org_a"], by=role_world["bootstrap"]
    )
    with pytest.raises(DirectAssignmentMutationError):
        ScopeAssignment.objects.filter(pk=assignment.pk).update(scope_id=str(role_world["org_b"].pk))


def test_role_permission_queryset_and_bulk_updates_are_guarded(role_world):
    """Guard direct queryset update(), bulk_update() and related-manager mutations on RolePermission."""
    role = RoleService.create(by=role_world["bootstrap"], name="reader_role", owner=role_world["org_a"])
    RoleService.grant_permissions(role, role_world["view"], by=role_world["bootstrap"])

    ScopeAssignment.objects.grant(
        user=role_world["outsider"], role=role, scope=role_world["org_a"], by=role_world["manager"]
    )
    assert engine.has_perm(role_world["outsider"], "things.view_thing", role_world["org_a"]) is True
    assert engine.has_perm(role_world["outsider"], "things.delete_thing", role_world["org_a"]) is False

    rp = RolePermission.objects.get(role=role, permission=role_world["view"])

    # 1. Direct queryset update() is rejected
    with pytest.raises(DirectRolePermissionMutationError):
        RolePermission.objects.filter(role=role, permission=role_world["view"]).update(permission=role_world["delete"])

    with pytest.raises(DirectRolePermissionMutationError):
        RolePermission.objects.filter(pk=rp.pk).update(role=None)

    # 2. Direct bulk_update() is rejected
    rp.permission = role_world["delete"]
    with pytest.raises(DirectRolePermissionMutationError):
        RolePermission.objects.bulk_update([rp], ["permission"])

    # 3. Related-manager update() and bulk_update() on role.role_permissions are rejected
    with pytest.raises(DirectRolePermissionMutationError):
        role.role_permissions.filter(permission=role_world["view"]).update(permission=role_world["delete"])

    with pytest.raises(DirectRolePermissionMutationError):
        role.role_permissions.bulk_update([rp], ["permission"])

    # 4. Reverse-relation update() and bulk_update() on permission.scoped_role_permissions are rejected
    other_role = RoleService.create(by=role_world["bootstrap"], name="other_role", owner=role_world["org_a"])
    with pytest.raises(DirectRolePermissionMutationError):
        role_world["view"].scoped_role_permissions.filter(role=role).update(role=other_role)

    rp.role = other_role
    with pytest.raises(DirectRolePermissionMutationError):
        role_world["view"].scoped_role_permissions.bulk_update([rp], ["role"])

    # 5. DirectRolePermissionMutationError is a subclass of DirectRoleMutationError
    assert issubclass(DirectRolePermissionMutationError, DirectRoleMutationError)

    # 6. Verify stored and effective permissions remain strictly unchanged
    role.refresh_from_db()
    assert list(role.permissions.all()) == [role_world["view"]]
    assert engine.has_perm(role_world["outsider"], "things.view_thing", role_world["org_a"]) is True
    assert engine.has_perm(role_world["outsider"], "things.delete_thing", role_world["org_a"]) is False


def test_role_and_assignment_bulk_updates_are_guarded(role_world):
    """Guard bulk_update() on Role and ScopeAssignment querysets."""
    role = RoleService.create(by=role_world["bootstrap"], name="bulk_role")
    role.name = "forged"
    with pytest.raises(DirectRoleMutationError, match="Bulk role updates must run through"):
        Role.objects.bulk_update([role], ["name"])

    role.refresh_from_db()
    assert role.name == "bulk_role"

    assignment = ScopeAssignment.objects.grant(
        user=role_world["outsider"], role=role, scope=role_world["org_a"], by=role_world["bootstrap"]
    )

    # bulk_update on status is rejected
    assignment.status = "SUSPENDED"
    with pytest.raises(InvalidAssignmentTransitionError, match="Assignment status must be changed through"):
        ScopeAssignment.objects.bulk_update([assignment], ["status"])

    assignment.refresh_from_db()
    assert assignment.status == "ACTIVE"

    # bulk_update on immutable fields is rejected
    assignment.scope_id = str(role_world["org_b"].pk)
    with pytest.raises(DirectAssignmentMutationError, match="immutable after creation"):
        ScopeAssignment.objects.bulk_update([assignment], ["scope_id"])

    assignment.refresh_from_db()
    assert assignment.scope == role_world["org_a"]
