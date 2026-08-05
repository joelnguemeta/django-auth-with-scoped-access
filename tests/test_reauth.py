"""ReAuth invalidation and credential-change integration."""

from __future__ import annotations

import pytest
from django.core.cache import cache

from scoped_access.reauth import ReAuthService
from scoped_access.reauth.service import GENERATION_PREFIX

INITIAL_PASSWORD = "initial-secret"
NEW_PASSWORD = "new-secret"


@pytest.fixture(autouse=True)
def reauth_settings(settings):
    settings.SCOPED_ACCESS = {"REAUTH": {"ENABLED": True, "TTL": 300}}
    cache.clear()
    yield
    cache.clear()


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create_user(username="reauth-user", password=INITIAL_PASSWORD)


@pytest.mark.django_db
def test_generation_invalidation_rejects_all_outstanding_tokens(user):
    first = ReAuthService.issue(user, password=INITIAL_PASSWORD)
    second = ReAuthService.issue(user, password=INITIAL_PASSWORD)

    ReAuthService.invalidate_all_for_user(user)

    assert ReAuthService.consume(first, user) is False
    assert ReAuthService.consume(second, user) is False

    fresh = ReAuthService.issue(user, password=INITIAL_PASSWORD)
    assert ReAuthService.consume(fresh, user) is True


@pytest.mark.django_db
def test_missing_generation_fails_closed(user):
    token = ReAuthService.issue(user, password=INITIAL_PASSWORD)

    cache.delete(f"{GENERATION_PREFIX}{user.pk}")

    assert ReAuthService.consume(token, user) is False


@pytest.mark.django_db
def test_password_change_automatically_invalidates_tokens(user):
    token = ReAuthService.issue(user, password=INITIAL_PASSWORD)

    user.set_password(NEW_PASSWORD)
    user.save(update_fields=["password"])

    assert ReAuthService.consume(token, user) is False
    fresh = ReAuthService.issue(user, password=NEW_PASSWORD)
    assert ReAuthService.consume(fresh, user) is True
