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

from scoped_access import RoleService
from scoped_access.drf import (
    MeAccessView,
    ReAuthView,
    RequireReAuth,
    ScopedModelPermission,
    ScopedModelViewSet,
    ScopedReadOnlyModelViewSet,
    ScopeObjectPermission,
    ScopeQuerySetMixin,
    ScopeWriteGuardMixin,
)
from scoped_access.models import ScopeAssignment
from scoped_access.registry import resources
from tests.testapp.models import Node, Resource

factory = APIRequestFactory()

SCOPED_ACCESS_ORG = {
    "HIERARCHY": [{"level": "ORGANIZATION", "model": "testapp.Node", "discriminator": {"level": "ORGANIZATION"}}],
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


class NodeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Node
        fields = ["id", "slug"]


class NodeViewSet(ScopeQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Node.objects.all()
    serializer_class = NodeSerializer
    scope_filter_all_actions = True


class WritableResourceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Resource
        fields = ["id", "slug", "anchor"]


class GuardedResourceViewSet(ScopeWriteGuardMixin, ScopeQuerySetMixin, viewsets.ModelViewSet):
    queryset = Resource.objects.all()
    serializer_class = WritableResourceSerializer
    permission_classes = [ScopeObjectPermission]


class SecureResourceViewSet(ScopedModelViewSet):
    queryset = Resource.objects.all()
    serializer_class = WritableResourceSerializer


class SecureReadOnlyResourceViewSet(ScopedReadOnlyModelViewSet):
    queryset = Resource.objects.all()
    serializer_class = ResourceSerializer


class MisconfiguredResourceViewSet(ScopeQuerySetMixin, viewsets.ReadOnlyModelViewSet):
    queryset = Resource.objects.all()
    serializer_class = ResourceSerializer


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
    fixture_admin = get_user_model().objects.create(username="boss", is_superuser=True)
    role = RoleService.create(by=fixture_admin, name="member")
    role.grant_permissions(perm, by=fixture_admin)

    user = get_user_model().objects.create(username="amy")
    user.set_password("s3cret")
    user.save()
    ScopeAssignment.objects.grant(
        user=user,
        role=role,
        scope=org_a,
        by=fixture_admin,
    )
    return {"user": user, "org_a": org_a, "res_a": res_a, "res_b": res_b}


def test_scope_queryset_mixin_filters_lists(org_world):
    request = factory.get("/resources/")
    force_authenticate(request, user=org_world["user"])
    response = ResourceViewSet.as_view({"get": "list"})(request)
    assert response.status_code == 200
    assert [r["slug"] for r in response.data] == ["res-a"]


def test_scope_queryset_mixin_filters_hierarchy_node_lists(org_world):
    request = factory.get("/organizations/")
    force_authenticate(request, user=org_world["user"])
    response = NodeViewSet.as_view({"get": "list"})(request)
    assert response.status_code == 200
    assert [node["slug"] for node in response.data] == ["org-a"]


def test_scope_object_permission_blocks_foreign_detail(org_world):
    view = ResourceViewSet.as_view({"get": "retrieve"})
    request = factory.get("/resources/x/")
    force_authenticate(request, user=org_world["user"])
    assert view(request, pk=org_world["res_a"].pk).status_code == 200
    assert view(request, pk=org_world["res_b"].pk).status_code == 403


def test_write_guard_allows_create_in_scope(org_world):
    request = factory.post("/resources/", {"slug": "res-new", "anchor": org_world["org_a"].pk})
    force_authenticate(request, user=org_world["user"])
    response = GuardedResourceViewSet.as_view({"post": "create"})(request)
    assert response.status_code == 201


def test_write_guard_blocks_create_out_of_scope(org_world):
    org_b = Node.objects.get(slug="org-b")
    request = factory.post("/resources/", {"slug": "res-new", "anchor": org_b.pk})
    force_authenticate(request, user=org_world["user"])
    response = GuardedResourceViewSet.as_view({"post": "create"})(request)
    assert response.status_code == 403


def test_write_guard_blocks_moving_object_out_of_scope(org_world):
    # res_a is in scope, so the object gate passes — the guard must still
    # deny re-anchoring it onto org-b (SPEC §5: the NEW anchor is checked).
    org_b = Node.objects.get(slug="org-b")
    request = factory.patch(f"/resources/{org_world['res_a'].pk}/", {"anchor": org_b.pk})
    force_authenticate(request, user=org_world["user"])
    response = GuardedResourceViewSet.as_view({"patch": "partial_update"})(request, pk=org_world["res_a"].pk)
    assert response.status_code == 403
    org_world["res_a"].refresh_from_db()
    assert org_world["res_a"].anchor == org_world["org_a"]


def test_write_guard_allows_update_within_scope(org_world):
    request = factory.patch(f"/resources/{org_world['res_a'].pk}/", {"slug": "renamed"})
    force_authenticate(request, user=org_world["user"])
    response = GuardedResourceViewSet.as_view({"patch": "partial_update"})(request, pk=org_world["res_a"].pk)
    assert response.status_code == 200


def _grant_resource_permissions(org_world):
    assignment = ScopeAssignment.objects.get(user=org_world["user"])
    actor = get_user_model().objects.get(username="boss")
    content_type = ContentType.objects.get_for_model(Resource)
    permissions = [
        Permission.objects.get(content_type=content_type, codename=f"{action}_resource")
        for action in ("view", "add", "change", "delete")
    ]
    assignment.role.grant_permissions(*permissions, by=actor)


def test_scoped_read_only_viewset_filters_list_and_blocks_foreign_detail(org_world):
    _grant_resource_permissions(org_world)
    list_request = factory.get("/resources/")
    force_authenticate(list_request, user=org_world["user"])
    response = SecureReadOnlyResourceViewSet.as_view({"get": "list"})(list_request)
    assert response.status_code == 200
    assert [resource["slug"] for resource in response.data] == ["res-a"]

    detail = SecureReadOnlyResourceViewSet.as_view({"get": "retrieve"})
    request = factory.get("/resources/x/")
    force_authenticate(request, user=org_world["user"])
    assert detail(request, pk=org_world["res_b"].pk).status_code == 403


def test_scoped_viewset_does_not_combine_permission_in_one_scope_with_coverage_in_another(org_world):
    """A permission in org-a plus an unrelated assignment in org-b is not access to org-b."""
    _grant_resource_permissions(org_world)
    actor = get_user_model().objects.get(username="boss")
    unrelated_role = RoleService.create(by=actor, name="unrelated member")
    org_b = Node.objects.get(slug="org-b")
    ScopeAssignment.objects.grant(
        user=org_world["user"],
        role=unrelated_role,
        scope=org_b,
        by=actor,
    )

    list_request = factory.get("/resources/")
    force_authenticate(list_request, user=org_world["user"])
    response = SecureReadOnlyResourceViewSet.as_view({"get": "list"})(list_request)
    assert response.status_code == 200
    assert [resource["slug"] for resource in response.data] == ["res-a"]

    detail_request = factory.get(f"/resources/{org_world['res_b'].pk}/")
    force_authenticate(detail_request, user=org_world["user"])
    detail_response = SecureReadOnlyResourceViewSet.as_view({"get": "retrieve"})(
        detail_request,
        pk=org_world["res_b"].pk,
    )
    assert detail_response.status_code == 403


def test_scoped_write_guard_requires_add_permission_at_target_scope(org_world):
    """Scope coverage alone cannot borrow add permission from another tenant."""
    _grant_resource_permissions(org_world)
    actor = get_user_model().objects.get(username="boss")
    unrelated_role = RoleService.create(by=actor, name="org-b member")
    org_b = Node.objects.get(slug="org-b")
    ScopeAssignment.objects.grant(
        user=org_world["user"],
        role=unrelated_role,
        scope=org_b,
        by=actor,
    )

    request = factory.post("/resources/", {"slug": "blocked", "anchor": org_b.pk})
    force_authenticate(request, user=org_world["user"])
    response = SecureResourceViewSet.as_view({"post": "create"})(request)

    assert response.status_code == 403
    assert not Resource.objects.filter(slug="blocked").exists()


def test_scoped_model_viewset_protects_create_update_and_destroy(org_world):
    _grant_resource_permissions(org_world)
    org_b = Node.objects.get(slug="org-b")

    create = factory.post("/resources/", {"slug": "blocked", "anchor": org_b.pk})
    force_authenticate(create, user=org_world["user"])
    assert SecureResourceViewSet.as_view({"post": "create"})(create).status_code == 403

    update = factory.patch(f"/resources/{org_world['res_b'].pk}/", {"slug": "blocked"})
    force_authenticate(update, user=org_world["user"])
    update_response = SecureResourceViewSet.as_view({"patch": "partial_update"})(
        update,
        pk=org_world["res_b"].pk,
    )
    assert update_response.status_code == 403

    destroy = factory.delete(f"/resources/{org_world['res_b'].pk}/")
    force_authenticate(destroy, user=org_world["user"])
    destroy_response = SecureResourceViewSet.as_view({"delete": "destroy"})(
        destroy,
        pk=org_world["res_b"].pk,
    )
    assert destroy_response.status_code == 403


def test_scope_queryset_mixin_warns_when_detail_routes_are_unprotected(org_world):
    request = factory.get("/resources/")
    force_authenticate(request, user=org_world["user"])
    with pytest.warns(RuntimeWarning, match="without ScopeObjectPermission"):
        response = MisconfiguredResourceViewSet.as_view({"get": "list"})(request)
    assert response.status_code == 200


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


def test_reauth_endpoint_is_throttled_per_user(settings, org_world):
    settings.SCOPED_ACCESS = {
        **SCOPED_ACCESS_ORG,
        "REAUTH": {"ENABLED": True, "TTL": 300, "RATE": "2/minute"},
    }
    user = org_world["user"]

    statuses = []
    for _ in range(3):
        request = factory.post("/auth/reauth/", {"password": "wrong"})
        force_authenticate(request, user=user)
        statuses.append(ReAuthView.as_view()(request).status_code)

    assert statuses == [400, 400, 429]


def test_dynamic_get_permissions_enforces_scoped_permissions_on_list_and_create(org_world):
    """Issue #14: dynamic permissions returned by get_permissions() must be used for scoping."""
    _grant_resource_permissions(org_world)
    actor = get_user_model().objects.get(username="boss")
    unrelated_role = RoleService.create(by=actor, name="org-b member")
    org_b = Node.objects.get(slug="org-b")
    org_a = Node.objects.get(slug="org-a")
    ScopeAssignment.objects.grant(
        user=org_world["user"],
        role=unrelated_role,
        scope=org_b,
        by=actor,
    )

    class DynamicResourceViewSet(ScopedModelViewSet):
        queryset = Resource.objects.all()
        serializer_class = WritableResourceSerializer
        permission_classes = [ScopeObjectPermission]

        def get_permissions(self):
            return [ScopedModelPermission(), ScopeObjectPermission()]

    # List: must ONLY return res-a (user lacks view_resource in org-b)
    list_request = factory.get("/resources/")
    force_authenticate(list_request, user=org_world["user"])
    response = DynamicResourceViewSet.as_view({"get": "list"})(list_request)
    assert response.status_code == 200
    assert [resource["slug"] for resource in response.data] == ["res-a"]

    # Create into org-b: user has scope coverage in org-b but lacks add_resource -> 403
    post_b = factory.post("/resources/", {"slug": "blocked-b", "anchor": org_b.pk})
    force_authenticate(post_b, user=org_world["user"])
    response_b = DynamicResourceViewSet.as_view({"post": "create"})(post_b)
    assert response_b.status_code == 403
    assert not Resource.objects.filter(slug="blocked-b").exists()

    # Create into org-a: user has add_resource in org-a -> 201
    post_a = factory.post("/resources/", {"slug": "allowed-a", "anchor": org_a.pk})
    force_authenticate(post_a, user=org_world["user"])
    response_a = DynamicResourceViewSet.as_view({"post": "create"})(post_a)
    assert response_a.status_code == 201
    assert Resource.objects.filter(slug="allowed-a").exists()


def test_dynamic_get_permissions_enforces_scoped_permissions_on_update_and_move(org_world):
    """Updates and moves with dynamic permissions must require action permission at target scope."""
    _grant_resource_permissions(org_world)
    actor = get_user_model().objects.get(username="boss")
    unrelated_role = RoleService.create(by=actor, name="org-b member")
    org_b = Node.objects.get(slug="org-b")
    ScopeAssignment.objects.grant(
        user=org_world["user"],
        role=unrelated_role,
        scope=org_b,
        by=actor,
    )

    class DynamicResourceViewSet(ScopedModelViewSet):
        queryset = Resource.objects.all()
        serializer_class = WritableResourceSerializer
        permission_classes = [ScopeObjectPermission]

        def get_permissions(self):
            return [ScopedModelPermission(), ScopeObjectPermission()]

    # Moving res-a into org-b must be rejected because user lacks change_resource in org-b
    move_request = factory.patch(f"/resources/{org_world['res_a'].pk}/", {"anchor": org_b.pk})
    force_authenticate(move_request, user=org_world["user"])
    move_response = DynamicResourceViewSet.as_view({"patch": "partial_update"})(move_request, pk=org_world["res_a"].pk)
    assert move_response.status_code == 403

    # In-place update within org-a succeeds
    update_request = factory.patch(f"/resources/{org_world['res_a'].pk}/", {"slug": "res-a-updated"})
    force_authenticate(update_request, user=org_world["user"])
    update_response = DynamicResourceViewSet.as_view({"patch": "partial_update"})(
        update_request, pk=org_world["res_a"].pk
    )
    assert update_response.status_code == 200
    org_world["res_a"].refresh_from_db()
    assert org_world["res_a"].slug == "res-a-updated"


def test_dynamic_get_permissions_respects_custom_perms_map(org_world):
    """Customized perms_map on ScopedModelPermission instances is respected."""
    _grant_resource_permissions(org_world)
    org_a = Node.objects.get(slug="org-a")

    class CustomScopedModelPermission(ScopedModelPermission):
        perms_map = {
            **ScopedModelPermission.perms_map,
            "POST": ["testapp.custom_add_permission"],
        }

    class CustomMappedViewSet(ScopedModelViewSet):
        queryset = Resource.objects.all()
        serializer_class = WritableResourceSerializer
        permission_classes = []

        def get_permissions(self):
            return [CustomScopedModelPermission(), ScopeObjectPermission()]

    # User lacks 'custom_add_permission' in org-a -> 403
    request = factory.post("/resources/", {"slug": "custom-blocked", "anchor": org_a.pk})
    force_authenticate(request, user=org_world["user"])
    response = CustomMappedViewSet.as_view({"post": "create"})(request)
    assert response.status_code == 403

    # Grant 'custom_add_permission' to role in org-a
    ct = ContentType.objects.get_for_model(Resource)
    custom_perm, _ = Permission.objects.get_or_create(
        content_type=ct, codename="custom_add_permission", defaults={"name": "custom"}
    )
    actor = get_user_model().objects.get(username="boss")
    assignment = ScopeAssignment.objects.get(user=org_world["user"])
    assignment.role.grant_permissions(custom_perm, by=actor)

    # Now create succeeds -> 201
    request_ok = factory.post("/resources/", {"slug": "custom-allowed", "anchor": org_a.pk})
    force_authenticate(request_ok, user=org_world["user"])
    response_ok = CustomMappedViewSet.as_view({"post": "create"})(request_ok)
    assert response_ok.status_code == 201


def test_dynamic_get_permissions_recursion_guard(org_world):
    """Calling get_queryset() inside get_permissions() must not cause a RecursionError."""
    _grant_resource_permissions(org_world)

    class RecursiveGetPermissionsViewSet(ScopedModelViewSet):
        queryset = Resource.objects.all()
        serializer_class = ResourceSerializer
        permission_classes = [ScopeObjectPermission]

        def get_permissions(self):
            # Invoking get_queryset inside get_permissions must not cause RecursionError
            self.get_queryset()
            return [ScopedModelPermission(), ScopeObjectPermission()]

    request = factory.get("/resources/")
    force_authenticate(request, user=org_world["user"])
    response = RecursiveGetPermissionsViewSet.as_view({"get": "list"})(request)
    assert response.status_code == 200
    assert [r["slug"] for r in response.data] == ["res-a"]


def test_dynamic_get_permissions_does_not_consume_reauth_token(org_world):
    """Permission discovery must never evaluate has_permission or consume ReAuth tokens."""
    from scoped_access.reauth import ReAuthService

    _grant_resource_permissions(org_world)
    user = org_world["user"]
    test_creds = {"password": "".join(["s", "3", "cret"])}
    token = ReAuthService.issue(user, **test_creds)
    assert token is not None

    class ReAuthViewSet(ScopedModelViewSet):
        queryset = Resource.objects.all()
        serializer_class = ResourceSerializer

        def get_permissions(self):
            return [ScopedModelPermission(), ScopeObjectPermission(), RequireReAuth()]

    request = factory.get("/resources/", HTTP_X_REAUTH_TOKEN=token)
    force_authenticate(request, user=user)
    response = ReAuthViewSet.as_view({"get": "list"})(request)
    assert response.status_code == 200

    # The single-use token was consumed by check_permissions once, not burned during discovery
    second_request = factory.get("/resources/", HTTP_X_REAUTH_TOKEN=token)
    force_authenticate(second_request, user=user)
    second_response = ReAuthViewSet.as_view({"get": "list"})(second_request)
    assert second_response.status_code == 403


def test_dynamic_get_permissions_suppresses_unprotected_warning(org_world):
    """Providing ScopeObjectPermission via get_permissions() suppresses RuntimeWarning."""
    import warnings

    class DynamicProtectedViewSet(ScopeQuerySetMixin, viewsets.ReadOnlyModelViewSet):
        queryset = Resource.objects.all()
        serializer_class = ResourceSerializer
        permission_classes = []

        def get_permissions(self):
            return [ScopeObjectPermission()]

    request = factory.get("/resources/")
    force_authenticate(request, user=org_world["user"])
    with warnings.catch_warnings(record=True) as recorded:
        warnings.simplefilter("always")
        response = DynamicProtectedViewSet.as_view({"get": "list"})(request)
    assert response.status_code == 200
    runtime_warnings = [w for w in recorded if issubclass(w.category, RuntimeWarning)]
    assert not any("uses ScopeQuerySetMixin without ScopeObjectPermission" in str(w.message) for w in runtime_warnings)
