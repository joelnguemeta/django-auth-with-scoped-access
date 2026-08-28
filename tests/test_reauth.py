"""ReAuth invalidation and credential-change integration."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from django.core.cache import cache

from scoped_access.reauth import ReAuthService, atomic
from scoped_access.reauth.service import GENERATION_PREFIX, TOKEN_PREFIX

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


@pytest.mark.django_db
def test_concurrent_consumption_has_exactly_one_winner(user, monkeypatch):
    token = ReAuthService.issue(user, password=INITIAL_PASSWORD)
    token_key = f"{TOKEN_PREFIX}{token}"
    barrier = Barrier(2)
    original_get = cache.get

    def racing_get(key, *args, **kwargs):
        value = original_get(key, *args, **kwargs)
        if key == token_key:
            barrier.wait(timeout=5)
        return value

    monkeypatch.setattr(cache, "get", racing_get)
    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: ReAuthService.consume(token, user), range(2)))

    assert sorted(results) == [False, True]


@pytest.mark.django_db
def test_inactive_users_cannot_issue_or_consume_tokens(user):
    token = ReAuthService.issue(user, password=INITIAL_PASSWORD)
    user.is_active = False
    user.save(update_fields=["is_active"])

    assert ReAuthService.issue(user, password=INITIAL_PASSWORD) is None
    assert ReAuthService.consume(token, user) is False
    assert cache.get(f"{TOKEN_PREFIX}{token}") is not None


def test_builtin_redis_path_uses_getdel(monkeypatch):
    payload = {"user_id": "1"}

    class Serializer:
        def loads(self, value):
            return value

    class Client:
        def __init__(self):
            self.keys = []

        def getdel(self, key):
            self.keys.append(key)
            return payload

    client = Client()

    class Internal:
        _serializer = Serializer()

        def get_client(self, key, *, write):
            assert write is True
            return client

    redis_backend_class = type(
        "RedisBackend",
        (),
        {
            "__module__": "django.core.cache.backends.redis",
            "_cache": Internal(),
            "make_and_validate_key": lambda self, key: f":1:{key}",
        },
    )
    monkeypatch.setattr(atomic, "caches", {"default": redis_backend_class()})

    assert atomic._redis_atomic_pop("token-key") == payload
    assert client.keys == [":1:token-key"]


def test_redis_getdel_falls_back_to_lua_on_older_servers():
    class ResponseError(Exception):
        pass

    class Client:
        def getdel(self, key):
            raise ResponseError("unknown command")

        def eval(self, script, key_count, key):
            assert script == atomic._GETDEL_LUA
            assert key_count == 1
            assert key == "token-key"
            return b"payload"

    assert atomic._getdel_or_lua(Client(), "token-key") == b"payload"
