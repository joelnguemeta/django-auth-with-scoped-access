"""Django-level guarantees not expressible in the JSON conformance format
(yet): duplicate prevention (SPEC §8.3) and event emission (SPEC §9).
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.db import IntegrityError, transaction

from scoped_access import signals
from scoped_access.models import AssignmentStatus, Role, ScopeAssignment
from tests.testapp.models import Node

SCOPED_ACCESS_ORG = {
    "HIERARCHY": [{"level": "ORGANIZATION", "model": "testapp.Node", "discriminator": {"level": "ORGANIZATION"}}],
}


@pytest.fixture
def world(settings, db):
    settings.SCOPED_ACCESS = SCOPED_ACCESS_ORG
    return {
        "user": get_user_model().objects.create(username="amy"),
        "admin": get_user_model().objects.create(username="boss"),
        "role": Role.objects.create(name="member"),
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
        user=world["user"], role=world["role"], level="ORGANIZATION", scope=world["org"]
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
        user=world["user"], role=world["role"], level=level
    )
    first = grant()

    with pytest.raises(IntegrityError), transaction.atomic():  # SPEC §8.3
        grant()

    first.revoke(by=world["admin"], reason="rotation")
    regrant = grant()
    assert regrant.status == AssignmentStatus.ACTIVE
    assert ScopeAssignment.objects.count() == 2


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
