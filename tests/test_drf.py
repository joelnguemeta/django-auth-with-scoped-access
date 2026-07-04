"""Smoke tests for the DRF glue — end-to-end over HTTP-shaped requests.

The engine's behaviour is covered by the conformance suite; here we verify
the DRF layer wires it correctly (filtering, object gate, step-up, /me/access/).
"""

from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from django.core.cache import cache
from rest_framework import serializers, viewsets
from rest_framework.test import APIRequestFactory, force_authenticate
from rest_framework.views import APIView

from scoped_access.drf import (
    MeAccessView,
    ReAuthView,
    RequireReAuth,
    ScopeObjectPermission,
    ScopeQuerySetMixin,
)
from scoped_access.models import Role, ScopeAssignment
from scoped_access.registry import resources
from tests.testapp.models import Node, Resource

factory = APIRequestFactory()

SCOPED_ACCESS_ORG = {
    "HIERARCHY": [
        {"level": "ORGANIZATION", "model": "testapp.Node", "discriminator": {"level": "ORGANIZATION"}}
    ],
    "ROLE_OWNER_LEVELS": [],
    "GRANTABLE_PERMISSIONS": "self",
    "REAUTH": {"ENABLED": True, "TTL": 300},
}


class ResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Resource
        fields = ["id", "slug"]


class ResourceViewSet(ScopeQuerySetMixin, viewsets.ModelViewSet):
    queryset = Resource.objects.all()
    serializer_class = ResourceSerializer
    permission_classes = [ScopeObjectPermission]


class SensitiveView(APIView):
    permission_classes = [RequireReAuth]

    def post(self, request):
        from rest_framework.response import Response

        return Response({"done": True})


@pytest.fixture
def org_world(settings, db):
    settings.SCOPED_ACCESS = SCOPED_ACCESS_ORG
    resources.clear()
    resources.register(Resource, anchor="anchor")
    cache.clear()

    org_a = Node.objects.create(slug="org-a", level="ORGANIZATION")
    org_b = Node.objects.create(slug="org-b", level="ORGANIZATION")
    res_a = Resource.objects.create(slug="res-a", anchor=org_a)
    res_b = Resource.objects.create(slug="res-b", anchor=org_b)

    ct, _ = ContentType.objects.get_or_create(app_label="things", model="thing")
    perm, _ = Permission.objects.get_or_create(content_type=ct, codename="view_thing", defaults={"name": "v"})
    role = Role.objects.create(name="member")
    role.permissions.add(perm)

    user = get_user_model().objects.create(username="amy")
    user.set_password("s3cret")
    user.save()
    ScopeAssignment.objects.create(
        user=user,
        role=role,
        level="ORGANIZATION",
        scope_ct=ContentType.objects.get_for_model(Node),
        scope_id=str(org_a.pk),
    )
    return {"user": user, "org_a": org_a, "res_a": res_a, "res_b": res_b}


def test_scope_queryset_mixin_filters_lists(org_world):
    request = factory.get("/resources/")
    force_authenticate(request, user=org_world["user"])
    response = ResourceViewSet.as_view({"get": "list"})(request)
    assert response.status_code == 200
    assert [r["slug"] for r in response.data] == ["res-a"]


def test_scope_object_permission_blocks_foreign_detail(org_world):
    view = ResourceViewSet.as_view({"get": "retrieve"})
    request = factory.get("/resources/x/")
    force_authenticate(request, user=org_world["user"])
    assert view(request, pk=org_world["res_a"].pk).status_code == 200
    assert view(request, pk=org_world["res_b"].pk).status_code == 403


def test_me_access_payload(org_world):
    request = factory.get("/me/access/")
    force_authenticate(request, user=org_world["user"])
    data = MeAccessView.as_view()(request).data
    assert data["principal"]["superuser"] is False
    assert data["permissions"] == ["things.view_thing"]
    assert data["assignments"][0]["role"]["name"] == "member"
    assert data["assignments"][0]["scope"]["label"] == "org-a (ORGANIZATION)"


def test_reauth_http_flow_single_use(org_world):
    user = org_world["user"]

    def sensitive(token=None):
        headers = {"HTTP_X_REAUTH_TOKEN": token} if token else {}
        request = factory.post("/sensitive/", **headers)
        force_authenticate(request, user=user)
        return SensitiveView.as_view()(request)

    # No token → 403 with the machine-readable flag (SPEC §7.3)
    denied = sensitive()
    assert denied.status_code == 403
    assert denied.data["reauth_required"] is True

    # Bad proof → 400, no token
    request = factory.post("/auth/reauth/", {"password": "wrong"})
    force_authenticate(request, user=user)
    assert ReAuthView.as_view()(request).status_code == 400

    # Good proof → token usable exactly once
    request = factory.post("/auth/reauth/", {"password": "s3cret"})
    force_authenticate(request, user=user)
    issued = ReAuthView.as_view()(request)
    assert issued.status_code == 200
    token = issued.data["reauth_token"]

    assert sensitive(token).status_code == 200
    assert sensitive(token).status_code == 403  # single use
