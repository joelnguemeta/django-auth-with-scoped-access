"""Django-level guarantees not expressible in the JSON conformance format
(yet): duplicate prevention (SPEC §8.3) and event emission (SPEC §9).
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError, transaction
from django.db.models.deletion import ProtectedError
from django.utils import timezone

from scoped_access import RoleService, signals
from scoped_access.exceptions import (
    AssignmentDeletionError,
    AssignmentManagementPermissionError,
    AssignmentScopeError,
    DirectAssignmentMutationError,
    InvalidAssignmentTransitionError,
    RoleAssignmentError,
)
from scoped_access.models import AssignmentStatus, ScopeAssignment
from tests.testapp.models import Node

SCOPED_ACCESS_ORG = {
    "HIERARCHY": [
        {"level": "ROOT"},
        {"level": "ORGANIZATION", "model": "testapp.Node", "discriminator": {"level": "ORGANIZATION"}},
    ],
}


@pytest.fixture
def world(settings, db):
    settings.SCOPED_ACCESS = SCOPED_ACCESS_ORG
    user = get_user_model().objects.create(username="amy")
    admin = get_user_model().objects.create(username="boss", is_superuser=True)
    return {
        "user": user,
        "admin": admin,
        "role": RoleService.create(by=admin, name="member"),
        "org": Node.objects.create(slug="org-a", level="ORGANIZATION"),
    }


class Recorder:
    def __init__(self, signal):
        self.calls: list[dict] = []
        signal.connect(self._receive, weak=False)
        self._signal = signal

    def _receive(self, sender, **kwargs):
        self.calls.append(kwargs)

    def disconnect(self):
        self._signal.disconnect(self._receive)


def test_duplicate_live_assignment_rejected_but_regrant_after_revoke_ok(world):
    grant = lambda: ScopeAssignment.objects.grant(  # noqa: E731
        user=world["user"], role=world["role"], by=world["admin"], level="ORGANIZATION", scope=world["org"]
    )
    first = grant()

    with pytest.raises(IntegrityError), transaction.atomic():  # SPEC §8.3
        grant()

    first.revoke(by=world["admin"], reason="rotation")
    regrant = grant()  # revoked rows don't block re-granting
    assert regrant.status == AssignmentStatus.ACTIVE
    assert ScopeAssignment.objects.count() == 2  # history preserved, no hard delete


@pytest.mark.parametrize("level", [None, "ROOT"], ids=["flat-rbac", "explicit-root"])
def test_duplicate_live_global_assignment_rejected_but_regrant_after_revoke_ok(world, level):
    grant = lambda: ScopeAssignment.objects.grant(  # noqa: E731
        user=world["user"], role=world["role"], by=world["admin"], level=level
    )
    first = grant()

    with pytest.raises(IntegrityError), transaction.atomic():  # SPEC §8.3
        grant()

    first.revoke(by=world["admin"], reason="rotation")
    regrant = grant()
    assert regrant.status == AssignmentStatus.ACTIVE
    assert ScopeAssignment.objects.count() == 2


def test_valid_lifecycle_transitions(world):
    assignment = ScopeAssignment.objects.grant(user=world["user"], role=world["role"], by=world["admin"])

    assignment.suspend(by=world["admin"])
    assert assignment.status == AssignmentStatus.SUSPENDED

    assignment.reactivate(by=world["admin"])
    assert assignment.status == AssignmentStatus.ACTIVE

    assignment.suspend(by=world["admin"])
    assignment.revoke(by=world["admin"], reason="offboarding")
    assignment.refresh_from_db()
    assert assignment.status == AssignmentStatus.REVOKED
    assert assignment.revoked_by == world["admin"]
    assert assignment.reason == "offboarding"


@pytest.mark.parametrize("operation", ["suspend", "reactivate", "revoke"])
def test_lifecycle_transitions_require_an_authorized_actor(world, operation):
    assignment = ScopeAssignment.objects.grant(
        user=world["user"],
        role=world["role"],
        by=world["admin"],
        level="ORGANIZATION",
        scope=world["org"],
    )
    if operation == "reactivate":
        assignment.suspend(by=world["admin"])
        expected_status = AssignmentStatus.SUSPENDED
    else:
        expected_status = AssignmentStatus.ACTIVE

    with pytest.raises(AssignmentManagementPermissionError):
        getattr(assignment, operation)(by=world["user"])
    with pytest.raises(AssignmentManagementPermissionError):
        getattr(assignment, operation)()

    assignment.refresh_from_db()
    assert assignment.status == expected_status


def test_lifecycle_authorization_uses_the_persisted_scope(world):
    other_org = Node.objects.create(slug="org-b", level="ORGANIZATION")
    manage_assignments = Permission.objects.get(
        content_type__app_label="scoped_access",
        codename="manage_assignments",
    )
    manager_role = RoleService.create(by=world["admin"], name="org-b assignment manager")
    manager_role.grant_permissions(manage_assignments, by=world["admin"])
    ScopeAssignment.objects.grant(
        user=world["user"],
        role=manager_role,
        by=world["admin"],
        level="ORGANIZATION",
        scope=other_org,
    )
    assignment = ScopeAssignment.objects.grant(
        user=world["user"],
        role=world["role"],
        by=world["admin"],
        level="ORGANIZATION",
        scope=world["org"],
    )

    assignment.scope = other_org
    with pytest.raises(AssignmentManagementPermissionError):
        assignment.revoke(by=world["user"])

    assignment.refresh_from_db()
    assert assignment.scope == world["org"]
    assert assignment.status == AssignmentStatus.ACTIVE


@pytest.mark.parametrize("operation", ["suspend", "reactivate", "revoke"])
def test_revoked_assignment_is_terminal(world, operation):
    assignment = ScopeAssignment.objects.grant(user=world["user"], role=world["role"], by=world["admin"])
    assignment.revoke(by=world["admin"])

    with pytest.raises(InvalidAssignmentTransitionError):
        getattr(assignment, operation)(by=world["admin"])

    assignment.refresh_from_db()
    assert assignment.status == AssignmentStatus.REVOKED


def test_direct_status_changes_are_rejected(world):
    assignment = ScopeAssignment.objects.grant(user=world["user"], role=world["role"], by=world["admin"])

    assignment.status = AssignmentStatus.SUSPENDED
    with pytest.raises(InvalidAssignmentTransitionError):
        assignment.save(update_fields=["status"])
    with pytest.raises(InvalidAssignmentTransitionError):
        ScopeAssignment.objects.filter(pk=assignment.pk).update(status=AssignmentStatus.SUSPENDED)

    assignment.refresh_from_db()
    assert assignment.status == AssignmentStatus.ACTIVE


@pytest.mark.parametrize("field", ["status", "granted_by", "revoked_by", "reason", "scope_id"])
def test_grant_rejects_forged_lifecycle_and_audit_fields(world, field):
    with pytest.raises(TypeError, match="Unsupported assignment fields"):
        ScopeAssignment.objects.grant(
            user=world["user"],
            role=world["role"],
            by=world["admin"],
            **{field: "forged"},
        )


def test_grant_rejects_non_root_level_without_scope(world):
    with pytest.raises(AssignmentScopeError):
        ScopeAssignment.objects.grant(
            user=world["user"],
            role=world["role"],
            by=world["admin"],
            level="ORGANIZATION",
        )


def test_grant_rejects_inverted_validity_window(world):
    valid_from = timezone.now()
    with pytest.raises(ValueError, match="valid_until must be later"):
        ScopeAssignment.objects.grant(
            user=world["user"],
            role=world["role"],
            by=world["admin"],
            valid_from=valid_from,
            valid_until=valid_from,
        )


def test_direct_validity_and_audit_mutations_are_rejected(world):
    assignment = ScopeAssignment.objects.grant(user=world["user"], role=world["role"], by=world["admin"])

    with pytest.raises(DirectAssignmentMutationError):
        ScopeAssignment.objects.filter(pk=assignment.pk).update(valid_until=timezone.now())

    assignment.reason = "forged"
    with pytest.raises(DirectAssignmentMutationError):
        assignment.save(update_fields=["reason"])
    with pytest.raises(DirectAssignmentMutationError):
        assignment.save()


def test_assignment_hard_delete_is_rejected(world):
    assignment = ScopeAssignment.objects.grant(user=world["user"], role=world["role"], by=world["admin"])

    with pytest.raises(AssignmentDeletionError):
        assignment.delete()
    with pytest.raises(AssignmentDeletionError):
        ScopeAssignment.objects.filter(pk=assignment.pk).delete()

    assert ScopeAssignment.objects.filter(pk=assignment.pk).exists()


def test_deleting_principal_cannot_cascade_assignment_history(world):
    assignment = ScopeAssignment.objects.grant(user=world["user"], role=world["role"], by=world["admin"])

    with pytest.raises(ProtectedError):
        world["user"].delete()

    assert ScopeAssignment.objects.filter(pk=assignment.pk).exists()


def test_lifecycle_events_emitted_with_actor(world):
    granted = Recorder(signals.assignment_granted)
    revoked = Recorder(signals.assignment_revoked)
    try:
        assignment = ScopeAssignment.objects.grant(
            user=world["user"],
            role=world["role"],
            level="ORGANIZATION",
            scope=world["org"],
            by=world["admin"],
        )
        assignment.revoke(by=world["admin"], reason="offboarding")
    finally:
        granted.disconnect()
        revoked.disconnect()

    assert granted.calls[0]["assignment"] == assignment
    assert granted.calls[0]["actor"] == world["admin"]
    assert revoked.calls[0]["reason"] == "offboarding"
    assignment.refresh_from_db()
    assert assignment.revoked_by == world["admin"]
    assert assignment.granted_by == world["admin"]


def test_assignment_grant_rolls_back_when_lifecycle_receiver_fails(world):
    def reject_audit_event(sender, **kwargs):
        raise RuntimeError("audit sink unavailable")

    uid = "test_assignment_grant_rolls_back"
    signals.assignment_granted.connect(reject_audit_event, weak=False, dispatch_uid=uid)
    try:
        with pytest.raises(RuntimeError, match="audit sink unavailable"):
            ScopeAssignment.objects.grant(
                user=world["user"],
                role=world["role"],
                scope=world["org"],
                by=world["admin"],
            )
    finally:
        signals.assignment_granted.disconnect(dispatch_uid=uid)

    assert not ScopeAssignment.objects.filter(user=world["user"], role=world["role"]).exists()


def test_role_permission_changes_emit_added_and_removed(world):
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    view = Permission.objects.create(content_type=ct, codename="view_thing", name="v")
    change = Permission.objects.create(content_type=ct, codename="change_thing", name="c")
    role = world["role"]

    recorder = Recorder(signals.role_permissions_changed)
    try:
        role.grant_permissions(view, change, by=world["admin"])
        role.grant_permissions(view, by=world["admin"])  # no-op: already granted
        role.revoke_permissions(change, by=world["admin"])
    finally:
        recorder.disconnect()

    assert len(recorder.calls) == 2  # the no-op emitted nothing
    assert recorder.calls[0]["added"] == ["things.change_thing", "things.view_thing"]
    assert recorder.calls[0]["actor"] == world["admin"]
    assert recorder.calls[1]["removed"] == ["things.change_thing"]


def test_assignment_reactivate_enforces_anti_escalation_r7_for_self(world):
    """R7: A manager cannot reactivate their own suspended assignment containing permissions they lack."""
    manage_assignments = Permission.objects.get(
        content_type__app_label="scoped_access",
        codename="manage_assignments",
    )
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    delete = Permission.objects.create(content_type=ct, codename="delete_thing", name="d")

    manager_role = RoleService.create(by=world["admin"], name="assignment manager")
    manager_role.grant_permissions(manage_assignments, by=world["admin"])
    ScopeAssignment.objects.grant(
        user=world["user"],
        role=manager_role,
        scope=world["org"],
        by=world["admin"],
    )

    privileged_role = RoleService.create(by=world["admin"], name="privileged role")
    privileged_role.grant_permissions(delete, by=world["admin"])
    privileged_assignment = ScopeAssignment.objects.grant(
        user=world["user"],
        role=privileged_role,
        scope=world["org"],
        by=world["admin"],
    )

    privileged_assignment.suspend(by=world["admin"])
    assert privileged_assignment.status == AssignmentStatus.SUSPENDED

    recorder = Recorder(signals.assignment_reactivated)
    try:
        with pytest.raises(RoleAssignmentError, match="cannot delegate this role"):
            privileged_assignment.reactivate(by=world["user"])
    finally:
        recorder.disconnect()

    # The assignment must remain SUSPENDED and emit no event
    privileged_assignment.refresh_from_db()
    assert privileged_assignment.status == AssignmentStatus.SUSPENDED
    assert len(recorder.calls) == 0


def test_assignment_reactivate_enforces_anti_escalation_r7_for_other_user(world):
    """R7: A manager cannot reactivate another user's suspended assignment containing permissions they lack."""
    manage_assignments = Permission.objects.get(
        content_type__app_label="scoped_access",
        codename="manage_assignments",
    )
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    delete = Permission.objects.create(content_type=ct, codename="delete_thing_other", name="do")

    manager = get_user_model().objects.create(username="manager_bob")
    manager_role = RoleService.create(by=world["admin"], name="manager bob role")
    manager_role.grant_permissions(manage_assignments, by=world["admin"])
    ScopeAssignment.objects.grant(
        user=manager,
        role=manager_role,
        scope=world["org"],
        by=world["admin"],
    )

    privileged_role = RoleService.create(by=world["admin"], name="privileged role other")
    privileged_role.grant_permissions(delete, by=world["admin"])
    privileged_assignment = ScopeAssignment.objects.grant(
        user=world["user"],
        role=privileged_role,
        scope=world["org"],
        by=world["admin"],
    )

    privileged_assignment.suspend(by=world["admin"])

    with pytest.raises(RoleAssignmentError, match="cannot delegate this role"):
        privileged_assignment.reactivate(by=manager)

    privileged_assignment.refresh_from_db()
    assert privileged_assignment.status == AssignmentStatus.SUSPENDED


def test_assignment_reactivate_blocks_manager_holding_permissions_at_different_scope(world):
    """R7: Holding permissions in organization B does not permit reactivating an assignment in organization A."""
    other_org = Node.objects.create(slug="org-b", level="ORGANIZATION")
    manage_assignments = Permission.objects.get(
        content_type__app_label="scoped_access",
        codename="manage_assignments",
    )
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    delete = Permission.objects.create(content_type=ct, codename="delete_thing_scoped", name="ds")

    manager = get_user_model().objects.create(username="scoped_manager")
    # Manager has manage_assignments in org-a
    manager_a_role = RoleService.create(by=world["admin"], name="manager a")
    manager_a_role.grant_permissions(manage_assignments, by=world["admin"])
    ScopeAssignment.objects.grant(user=manager, role=manager_a_role, scope=world["org"], by=world["admin"])

    # Manager has delete permission ONLY in org-b
    manager_b_role = RoleService.create(by=world["admin"], name="manager b")
    manager_b_role.grant_permissions(delete, by=world["admin"])
    ScopeAssignment.objects.grant(user=manager, role=manager_b_role, scope=other_org, by=world["admin"])

    # Target assignment is in org-a
    privileged_role = RoleService.create(by=world["admin"], name="privileged org a")
    privileged_role.grant_permissions(delete, by=world["admin"])
    target_assignment = ScopeAssignment.objects.grant(
        user=world["user"],
        role=privileged_role,
        scope=world["org"],
        by=world["admin"],
    )
    target_assignment.suspend(by=world["admin"])

    # Attempting to reactivate target assignment in org-a must fail because manager lacks delete in org-a
    with pytest.raises(RoleAssignmentError, match="cannot delegate this role"):
        target_assignment.reactivate(by=manager)

    target_assignment.refresh_from_db()
    assert target_assignment.status == AssignmentStatus.SUSPENDED


def test_assignment_reactivate_succeeds_when_actor_holds_permissions_or_is_superuser(world):
    """Reactivation succeeds when actor has required permissions at target scope, or is a superuser."""
    manage_assignments = Permission.objects.get(
        content_type__app_label="scoped_access",
        codename="manage_assignments",
    )
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    view = Permission.objects.create(content_type=ct, codename="view_thing_reactivate", name="vr")

    manager = get_user_model().objects.create(username="authorized_manager")
    manager_role = RoleService.create(by=world["admin"], name="authorized manager role")
    manager_role.grant_permissions(manage_assignments, view, by=world["admin"])
    ScopeAssignment.objects.grant(user=manager, role=manager_role, scope=world["org"], by=world["admin"])

    target_role = RoleService.create(by=world["admin"], name="target role")
    target_role.grant_permissions(view, by=world["admin"])
    assignment = ScopeAssignment.objects.grant(
        user=world["user"], role=target_role, scope=world["org"], by=world["admin"]
    )
    assignment.suspend(by=world["admin"])

    recorder = Recorder(signals.assignment_reactivated)
    try:
        # Authorized manager reactivates
        assignment.reactivate(by=manager)
        assert assignment.status == AssignmentStatus.ACTIVE
        assert len(recorder.calls) == 1
        assert recorder.calls[0]["actor"] == manager

        # Superuser can also reactivate
        assignment.suspend(by=world["admin"])
        assignment.reactivate(by=world["admin"])
        assert assignment.status == AssignmentStatus.ACTIVE
        assert len(recorder.calls) == 2
        assert recorder.calls[1]["actor"] == world["admin"]
    finally:
        recorder.disconnect()


def test_assignment_reactivate_respects_explicit_grant_policies(world, settings):
    """Explicit grant policies (any, list, callable) decide positive and negative reactivation."""
    manage_assignments = Permission.objects.get(
        content_type__app_label="scoped_access",
        codename="manage_assignments",
    )
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    perm1 = Permission.objects.create(content_type=ct, codename="perm_one", name="p1")
    perm2 = Permission.objects.create(content_type=ct, codename="perm_two", name="p2")

    manager = get_user_model().objects.create(username="policy_manager")
    manager_role = RoleService.create(by=world["admin"], name="policy manager role")
    manager_role.grant_permissions(manage_assignments, by=world["admin"])
    ScopeAssignment.objects.grant(user=manager, role=manager_role, scope=world["org"], by=world["admin"])

    role_1 = RoleService.create(by=world["admin"], name="role one", permissions=[perm1])
    role_2 = RoleService.create(by=world["admin"], name="role two", permissions=[perm2])
    assign_1 = ScopeAssignment.objects.grant(user=world["user"], role=role_1, scope=world["org"], by=world["admin"])
    assign_2 = ScopeAssignment.objects.grant(user=world["user"], role=role_2, scope=world["org"], by=world["admin"])
    assign_1.suspend(by=world["admin"])
    assign_2.suspend(by=world["admin"])

    # 1. Policy 'any': manager can reactivate even without held permissions
    settings.SCOPED_ACCESS = {**SCOPED_ACCESS_ORG, "GRANTABLE_PERMISSIONS": "any"}
    assign_1.reactivate(by=manager)
    assert assign_1.status == AssignmentStatus.ACTIVE
    assign_1.suspend(by=world["admin"])

    # 2. Policy list: allow perm1, forbid perm2; multi-permission role requires ALL permissions
    role_multi = RoleService.create(by=world["admin"], name="role multi", permissions=[perm1, perm2])
    assign_multi = ScopeAssignment.objects.grant(
        user=world["user"], role=role_multi, scope=world["org"], by=world["admin"]
    )
    assign_multi.suspend(by=world["admin"])

    settings.SCOPED_ACCESS = {**SCOPED_ACCESS_ORG, "GRANTABLE_PERMISSIONS": ["things.perm_one"]}
    assign_1.reactivate(by=manager)  # positive: perm_one allowed
    assert assign_1.status == AssignmentStatus.ACTIVE

    with pytest.raises(RoleAssignmentError):  # negative: perm_two forbidden
        assign_2.reactivate(by=manager)
    assert assign_2.status == AssignmentStatus.SUSPENDED

    with pytest.raises(RoleAssignmentError):  # negative: role_multi has perm2 which is forbidden
        assign_multi.reactivate(by=manager)
    assert assign_multi.status == AssignmentStatus.SUSPENDED

    # Policy list containing both permissions allows reactivating role_multi
    settings.SCOPED_ACCESS = {**SCOPED_ACCESS_ORG, "GRANTABLE_PERMISSIONS": ["things.perm_one", "things.perm_two"]}
    assign_multi.reactivate(by=manager)
    assert assign_multi.status == AssignmentStatus.ACTIVE
    assign_multi.suspend(by=world["admin"])

    # 3. Policy callable: custom decision across all permissions of the role
    settings.SCOPED_ACCESS = {
        **SCOPED_ACCESS_ORG,
        "GRANTABLE_PERMISSIONS": lambda actor, role, permission, at=None: permission == "things.perm_one",
    }
    assign_1.suspend(by=world["admin"])
    assign_1.reactivate(by=manager)  # positive: perm_one allowed
    assert assign_1.status == AssignmentStatus.ACTIVE

    with pytest.raises(RoleAssignmentError):  # negative: perm_two rejected
        assign_2.reactivate(by=manager)
    assert assign_2.status == AssignmentStatus.SUSPENDED

    with pytest.raises(RoleAssignmentError):  # negative: role_multi contains rejected perm_two
        assign_multi.reactivate(by=manager)
    assert assign_multi.status == AssignmentStatus.SUSPENDED


def test_revoked_assignment_reactivate_raises_invalid_transition_before_r7(world):
    """Exception priority: A REVOKED assignment raises InvalidAssignmentTransitionError, not RoleAssignmentError."""
    manage_assignments = Permission.objects.get(
        content_type__app_label="scoped_access",
        codename="manage_assignments",
    )
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    delete = Permission.objects.create(content_type=ct, codename="delete_thing_priority", name="dp")

    manager = get_user_model().objects.create(username="priority_manager")
    manager_role = RoleService.create(by=world["admin"], name="priority manager role")
    manager_role.grant_permissions(manage_assignments, by=world["admin"])
    ScopeAssignment.objects.grant(user=manager, role=manager_role, scope=world["org"], by=world["admin"])

    privileged_role = RoleService.create(by=world["admin"], name="privileged priority role", permissions=[delete])
    assignment = ScopeAssignment.objects.grant(
        user=world["user"], role=privileged_role, scope=world["org"], by=world["admin"]
    )
    assignment.revoke(by=world["admin"], reason="terminal")

    # Manager does NOT hold delete permission, but assignment is REVOKED
    # Must raise InvalidAssignmentTransitionError, NOT RoleAssignmentError
    with pytest.raises(InvalidAssignmentTransitionError, match="Cannot transition assignment from REVOKED to ACTIVE"):
        assignment.reactivate(by=manager)

    # Even if in-memory status was tampered with, persisted state in DB takes priority
    assignment.status = AssignmentStatus.SUSPENDED
    with pytest.raises(InvalidAssignmentTransitionError, match="Cannot transition assignment from REVOKED to ACTIVE"):
        assignment.reactivate(by=manager)

    assignment.refresh_from_db()
    assert assignment.status == AssignmentStatus.REVOKED


def test_suspend_and_revoke_do_not_require_holding_role_permissions(world):
    """Reducing authority (suspend/revoke) only requires manage_assignments, not R7 permission possession."""
    manage_assignments = Permission.objects.get(
        content_type__app_label="scoped_access",
        codename="manage_assignments",
    )
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    delete = Permission.objects.create(content_type=ct, codename="delete_thing_reduction", name="dr")

    manager = get_user_model().objects.create(username="reduction_manager")
    manager_role = RoleService.create(by=world["admin"], name="reduction manager role")
    manager_role.grant_permissions(manage_assignments, by=world["admin"])
    ScopeAssignment.objects.grant(user=manager, role=manager_role, scope=world["org"], by=world["admin"])

    privileged_role = RoleService.create(by=world["admin"], name="privileged reduction role", permissions=[delete])
    assignment = ScopeAssignment.objects.grant(
        user=world["user"], role=privileged_role, scope=world["org"], by=world["admin"]
    )

    # Manager does NOT hold delete permission, but CAN suspend and revoke
    assignment.suspend(by=manager)
    assert assignment.status == AssignmentStatus.SUSPENDED

    assignment.revoke(by=manager, reason="revoked by manager")
    assert assignment.status == AssignmentStatus.REVOKED
