"""ScopedModelAdmin: the Django admin applies scoped permissions per object."""

from __future__ import annotations

import pytest
from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.exceptions import PermissionDenied
from django.test import RequestFactory

from scoped_access import RoleService
from scoped_access.admin import ScopedModelAdmin
from scoped_access.models import ScopeAssignment
from scoped_access.registry import resources
from tests.testapp.models import Node, Resource

SCOPED_ACCESS_ORG = {
    "HIERARCHY": [{"level": "ORGANIZATION", "model": "testapp.Node", "discriminator": {"level": "ORGANIZATION"}}],
}


def _perms(*actions):
    ct = ContentType.objects.get_for_model(Resource)
    return [Permission.objects.get(content_type=ct, codename=f"{action}_resource") for action in actions]


@pytest.fixture
def world(settings, db):
    """amy: full rights in org-a, view-only in org-b, nothing in org-c."""
    settings.SCOPED_ACCESS = SCOPED_ACCESS_ORG
    resources.clear()
    resources.register(Resource, anchor="anchor")
    org_a = Node.objects.create(slug="org-a", level="ORGANIZATION")
    org_b = Node.objects.create(slug="org-b", level="ORGANIZATION")
    boss = get_user_model().objects.create(username="boss", is_superuser=True)
    full = RoleService.create(by=boss, name="full", permissions=_perms("view", "add", "change", "delete"))
    viewer = RoleService.create(by=boss, name="viewer", permissions=_perms("view"))
    amy = get_user_model().objects.create(username="amy", is_staff=True)
    ScopeAssignment.objects.grant(user=amy, role=full, scope=org_a, by=boss)
    ScopeAssignment.objects.grant(user=amy, role=viewer, scope=org_b, by=boss)
    yield {
        "boss": boss,
        "amy": amy,
        "org_a": org_a,
        "org_b": org_b,
        "res_a": Resource.objects.create(slug="res-a", anchor=org_a),
        "res_b": Resource.objects.create(slug="res-b", anchor=org_b),
        "res_c": Resource.objects.create(slug="res-c", anchor=Node.objects.create(slug="org-c", level="ORGANIZATION")),
    }
    resources.clear()


def _request(user):
    request = RequestFactory().post("/")
    request.user = user
    return request


def _admin():
    return ScopedModelAdmin(Resource, admin.site)


def test_change_list_shows_rows_where_view_is_held(world):
    slugs = set(_admin().get_queryset(_request(world["amy"])).values_list("slug", flat=True))
    assert slugs == {"res-a", "res-b"}


def test_object_permissions_are_checked_in_the_object_scope(world):
    model_admin, request = _admin(), _request(world["amy"])
    assert model_admin.has_change_permission(request, world["res_a"])
    assert model_admin.has_delete_permission(request, world["res_a"])
    # Stock ModelAdmin would say yes: amy holds change_resource somewhere.
    assert admin.ModelAdmin(Resource, admin.site).has_change_permission(request, world["res_b"])
    assert not model_admin.has_change_permission(request, world["res_b"])
    assert not model_admin.has_delete_permission(request, world["res_b"])


def test_save_guards_the_target_and_the_stored_scope(world):
    model_admin, request = _admin(), _request(world["amy"])
    model_admin.save_model(request, Resource(slug="new-a", anchor=world["org_a"]), None, change=False)
    assert Resource.objects.filter(slug="new-a").exists()

    with pytest.raises(PermissionDenied):
        model_admin.save_model(request, Resource(slug="new-b", anchor=world["org_b"]), None, change=False)

    moved = Resource.objects.get(slug="res-a")
    moved.anchor = world["org_b"]
    with pytest.raises(PermissionDenied):
        model_admin.save_model(request, moved, None, change=True)

    # list_editable path: an edit that pulls a foreign object into amy's scope.
    pulled = Resource.objects.get(slug="res-b")
    pulled.anchor = world["org_a"]
    with pytest.raises(PermissionDenied):
        model_admin.save_model(request, pulled, None, change=True)
    assert Resource.objects.get(slug="res-b").anchor == world["org_b"]


def test_bulk_delete_refuses_out_of_scope_objects(world):
    model_admin, request = _admin(), _request(world["amy"])
    with pytest.raises(PermissionDenied):
        model_admin.delete_queryset(request, Resource.objects.all())
    assert Resource.objects.count() == 3

    model_admin.delete_queryset(request, Resource.objects.filter(slug="res-a"))
    assert sorted(Resource.objects.values_list("slug", flat=True)) == ["res-b", "res-c"]


def test_node_dropdown_offers_only_writable_scopes(world):
    field = Resource._meta.get_field("anchor")
    formfield = _admin().formfield_for_foreignkey(field, _request(world["amy"]))
    assert list(formfield.queryset) == [world["org_a"]]


def test_no_permission_implies_another(world):
    """change_resource without view_resource does not reveal rows (SPEC §5)."""
    changer = RoleService.create(by=world["boss"], name="changer", permissions=_perms("change"))
    cid = get_user_model().objects.create(username="cid", is_staff=True)
    ScopeAssignment.objects.grant(user=cid, role=changer, scope=world["org_a"], by=world["boss"])
    assert not _admin().get_queryset(_request(cid)).exists()


def test_superuser_sees_and_edits_everything(world):
    model_admin, request = _admin(), _request(world["boss"])
    assert model_admin.get_queryset(request).count() == 3
    assert model_admin.has_change_permission(request, world["res_b"])
