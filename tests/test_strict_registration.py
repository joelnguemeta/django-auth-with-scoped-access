from __future__ import annotations

import pytest
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType

from scoped_access import RoleService, engine, register_global
from scoped_access.checks import check_scoped_access_config
from scoped_access.models import ScopeAssignment
from scoped_access.registry import resources
from tests.testapp.models import GlobalThing, Resource


@pytest.fixture(autouse=True)
def clean_registry():
    resources.clear()
    yield
    resources.clear()


@pytest.fixture
def registration_world(settings, django_user_model, db):
    settings.SCOPED_ACCESS = {
        "HIERARCHY": [
            {"level": "ROOT"},
            {"level": "ORGANIZATION", "model": "testapp.Node"},
        ],
    }
    admin = django_user_model.objects.create(username="admin", is_superuser=True)
    user = django_user_model.objects.create(username="member")
    content_type = ContentType.objects.get_for_model(GlobalThing)
    permission = Permission.objects.get(content_type=content_type, codename="view_globalthing")
    role = RoleService.create(by=admin, name="global-reader")
    role.grant_permissions(permission, by=admin)
    assignment = ScopeAssignment.objects.grant(user=user, role=role, level="ROOT", by=admin)
    thing = GlobalThing.objects.create(slug="global")
    return {
        "admin": admin,
        "assignment": assignment,
        "permission": f"{content_type.app_label}.{permission.codename}",
        "thing": thing,
        "user": user,
    }


def test_unregistered_models_remain_global_by_default(registration_world):
    world = registration_world
    assert engine.resolve_anchor(world["thing"]) == (engine.GLOBAL, None)
    assert engine.has_perm(world["user"], world["permission"], world["thing"])
    assert engine.visible_resources(world["user"], GlobalThing).filter(pk=world["thing"].pk).exists()


def test_strict_registration_denies_unregistered_models(settings, registration_world):
    settings.SCOPED_ACCESS["STRICT_REGISTRATION"] = True
    world = registration_world

    assert engine.resolve_anchor(world["thing"]) == (engine.UNREGISTERED, None)
    assert not engine.covers(world["assignment"], world["thing"])
    assert not engine.user_covers(world["user"], world["thing"])
    assert not engine.has_perm(world["user"], world["permission"], world["thing"])
    assert not engine.visible_resources(world["user"], GlobalThing).exists()


def test_explicit_global_model_remains_accessible_in_strict_mode(settings, registration_world):
    settings.SCOPED_ACCESS["STRICT_REGISTRATION"] = True
    register_global(GlobalThing)
    world = registration_world

    assert engine.resolve_anchor(world["thing"]) == (engine.GLOBAL, None)
    assert engine.has_perm(world["user"], world["permission"], world["thing"])
    assert engine.visible_resources(world["user"], GlobalThing).filter(pk=world["thing"].pk).exists()


def test_superuser_bypasses_strict_registration(settings, registration_world):
    settings.SCOPED_ACCESS["STRICT_REGISTRATION"] = True
    world = registration_world

    assert engine.has_perm(world["admin"], world["permission"], world["thing"])
    assert engine.user_covers(world["admin"], world["thing"])
    assert engine.visible_resources(world["admin"], GlobalThing).filter(pk=world["thing"].pk).exists()


def test_strict_registration_setting_must_be_boolean(settings):
    settings.SCOPED_ACCESS = {"STRICT_REGISTRATION": "yes"}
    assert "scoped_access.E011" in {error.id for error in check_scoped_access_config(None)}


def test_strict_registration_check_reports_unregistered_host_models(settings):
    settings.SCOPED_ACCESS = {
        "HIERARCHY": [{"level": "ORGANIZATION", "model": "testapp.Node"}],
        "STRICT_REGISTRATION": True,
    }
    errors = check_scoped_access_config(None)
    assert {error.obj for error in errors if error.id == "scoped_access.E012"} == {GlobalThing, Resource}


def test_strict_registration_check_accepts_explicit_models(settings):
    settings.SCOPED_ACCESS = {
        "HIERARCHY": [{"level": "ORGANIZATION", "model": "testapp.Node"}],
        "STRICT_REGISTRATION": True,
    }
    resources.register(Resource, anchor="anchor")
    register_global(GlobalThing)
    assert "scoped_access.E012" not in {error.id for error in check_scoped_access_config(None)}
