"""Per-request cache (SPEC §11): memoizes within a request, never across,
and lifecycle APIs invalidate it in-place.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.utils import timezone

from scoped_access import engine
from scoped_access.cache import request_cache
from scoped_access.models import Role, ScopeAssignment
from tests.testapp.models import Node

SCOPED_ACCESS_ORG = {
    "HIERARCHY": [{"level": "ORGANIZATION", "model": "testapp.Node", "discriminator": {"level": "ORGANIZATION"}}],
}


@pytest.fixture
def world(settings, db):
    settings.SCOPED_ACCESS = SCOPED_ACCESS_ORG
    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    view = Permission.objects.create(content_type=ct, codename="view_thing", name="v")
    change = Permission.objects.create(content_type=ct, codename="change_thing", name="c")
    role = Role.objects.create(name="member")
    admin = get_user_model().objects.create(username="boss", is_superuser=True)
    role.grant_permissions(view, by=admin)
    user = get_user_model().objects.create(username="amy")
    org = Node.objects.create(slug="org-a", level="ORGANIZATION")
    ScopeAssignment.objects.grant(user=user, role=role, level="ORGANIZATION", scope=org, valid_from=timezone.now())
    return {"user": user, "admin": admin, "role": role, "org": org, "change": change}


def test_memoizes_within_request(world, django_assert_num_queries):
    user = world["user"]
    with request_cache():
        assert engine.user_permissions(user) == {"things.view_thing"}
        with django_assert_num_queries(0):
            assert engine.user_permissions(user) == {"things.view_thing"}
            assert engine.has_perm(user, "things.view_thing") is True


def test_no_memoization_without_store(world, django_assert_num_queries):
    with pytest.raises(pytest.fail.Exception):  # proves the second call still queries
        engine.user_permissions(world["user"])
        with django_assert_num_queries(0):
            engine.user_permissions(world["user"])


def test_explicit_clock_bypasses_cache(world):
    user = world["user"]
    with request_cache():
        engine.user_permissions(user)  # warm the "now" entry
        past = datetime(2020, 1, 1, tzinfo=UTC)  # before the grant's valid_from
        assert engine.user_permissions(user, at=past) == set()


def test_lifecycle_apis_invalidate_within_request(world):
    user, role = world["user"], world["role"]
    with request_cache():
        assert engine.user_permissions(user) == {"things.view_thing"}  # warm

        role.grant_permissions(world["change"], by=world["admin"])
        assert engine.user_permissions(user) == {"things.view_thing", "things.change_thing"}

        assignment = ScopeAssignment.objects.filter(user=user).first()
        assignment.revoke(reason="test")
        assert engine.user_permissions(user) == set()
