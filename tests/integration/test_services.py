"""Real-service tests for locks, uniqueness and cross-process token use."""

from concurrent.futures import ThreadPoolExecutor
from multiprocessing import get_context
from threading import Barrier, Event
from time import monotonic
from types import SimpleNamespace

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.core.cache import cache
from django.db import IntegrityError, close_old_connections, connection, transaction

from scoped_access import RoleService
from scoped_access.exceptions import InvalidAssignmentTransitionError, RoleAssignmentError
from scoped_access.models import ScopeAssignment
from scoped_access.reauth import ReAuthService
from scoped_access.reauth.service import FRESH_PREFIX
from tests.integration.redis_worker import consume

pytestmark = [
    pytest.mark.django_db(transaction=True),
    pytest.mark.skipif(connection.vendor != "postgresql", reason="requires PostgreSQL integration settings"),
]


@pytest.fixture
def world():
    users = get_user_model()
    admin = users.objects.create(username="admin", is_superuser=True)
    user = users.objects.create(username="user")
    role = RoleService.create(by=admin, name="role")
    return admin, user, role


def _parallel(work):
    barrier = Barrier(2)

    def run():
        close_old_connections()
        try:
            barrier.wait(timeout=10)
            return work()
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        return list(pool.map(lambda _: run(), range(2)))


def test_concurrent_duplicate_grants_are_rejected(world):
    admin, user, role = world

    def grant():
        try:
            ScopeAssignment.objects.grant(user=user, role=role, by=admin)
            return "granted"
        except IntegrityError:
            return "duplicate"

    assert sorted(_parallel(grant)) == ["duplicate", "granted"]
    assert ScopeAssignment.objects.filter(user=user, role=role).count() == 1


def test_concurrent_revocation_has_one_winner(world):
    admin, user, role = world
    assignment = ScopeAssignment.objects.grant(user=user, role=role, by=admin)

    def revoke():
        instance = ScopeAssignment.objects.get(pk=assignment.pk)
        try:
            instance.revoke(by=admin)
            return "revoked"
        except InvalidAssignmentTransitionError:
            return "rejected"

    assert sorted(_parallel(revoke)) == ["rejected", "revoked"]
    assignment.refresh_from_db()
    assert assignment.status == "REVOKED"


def test_grant_waits_for_role_permission_change(world):
    admin, user, role = world
    manager = get_user_model().objects.create(username="manager")
    manage = Permission.objects.get(content_type__app_label="scoped_access", codename="manage_assignments")
    dangerous = Permission.objects.get(content_type__app_label="auth", codename="delete_user")
    manager_role = RoleService.create(by=admin, name="manager", permissions=[manage])
    ScopeAssignment.objects.grant(user=manager, role=manager_role, by=admin)
    locked, attempted, release = Event(), Event(), Event()
    backend_pid = []

    def edit():
        close_old_connections()
        try:
            with transaction.atomic():
                role.grant_permissions(dangerous, by=admin)
                locked.set()
                assert release.wait(timeout=10)
        finally:
            close_old_connections()

    def grant():
        close_old_connections()
        try:
            assert locked.wait(timeout=10)
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_backend_pid()")
                backend_pid.append(cursor.fetchone()[0])
            attempted.set()
            try:
                ScopeAssignment.objects.grant(user=user, role=role, by=manager)
                return "granted"
            except RoleAssignmentError:
                return "rejected"
        finally:
            close_old_connections()

    with ThreadPoolExecutor(max_workers=2) as pool:
        editor = pool.submit(edit)
        granting = pool.submit(grant)
        try:
            assert attempted.wait(timeout=10)
            deadline = monotonic() + 10
            while monotonic() < deadline:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT wait_event_type FROM pg_stat_activity WHERE pid = %s", [backend_pid[0]])
                    row = cursor.fetchone()
                if row and row[0] == "Lock":
                    break
                assert not granting.done(), "grant completed without waiting for the role lock"
                Event().wait(0.01)
            else:
                pytest.fail("grant did not wait for the role lock")
        finally:
            release.set()
        editor.result(timeout=10)
        assert granting.result(timeout=10) == "rejected"
    assert not ScopeAssignment.objects.filter(user=user, role=role).exists()


@pytest.mark.parametrize("mode,fresh", [("single_use", False), ("window", True)])
def test_redis_consumption_across_processes(settings, mode, fresh):
    settings.SCOPED_ACCESS = {"REAUTH": {"ENABLED": True, "TTL": 300, "MODE": mode}}
    test_proof = "x"
    user = SimpleNamespace(pk="integration", is_active=True, check_password=lambda value: value == test_proof)
    token = ReAuthService.issue(user, password=test_proof)
    ctx = get_context("spawn")
    barrier, queue = ctx.Barrier(4), ctx.Queue()
    # Spawned workers use the integration settings module, so pass the mode
    # explicitly through the environment for their independent Django setup.
    import os

    previous = os.environ.get("SCOPED_TEST_REAUTH_MODE")
    os.environ["SCOPED_TEST_REAUTH_MODE"] = mode
    processes = [ctx.Process(target=consume, args=(token, user.pk, fresh, barrier, queue)) for _ in range(4)]
    try:
        for process in processes:
            process.start()
        results = [queue.get(timeout=20) for _ in processes]
        for process in processes:
            process.join(timeout=10)
            assert process.exitcode == 0
        assert sorted(results) == [False, False, False, True]
        assert ReAuthService.consume(token, user) is (mode == "window")
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()
                process.join()
        if previous is None:
            os.environ.pop("SCOPED_TEST_REAUTH_MODE", None)
        else:
            os.environ["SCOPED_TEST_REAUTH_MODE"] = previous
        queue.close()


def test_redis_freshness_state_loss_fails_closed(settings):
    settings.SCOPED_ACCESS = {"REAUTH": {"ENABLED": True, "TTL": 300, "MODE": "window"}}
    test_proof = "x"
    user = SimpleNamespace(pk="integration", is_active=True, check_password=lambda value: value == test_proof)
    token = ReAuthService.issue(user, password=test_proof)

    cache.delete(f"{FRESH_PREFIX}{token}")
    assert ReAuthService.consume(token, user, fresh=True) is False
    assert ReAuthService.consume(token, user) is True
