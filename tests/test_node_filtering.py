from __future__ import annotations

import pytest
from django.contrib.auth import get_user_model

from scoped_access import RoleService, engine
from scoped_access.models import ScopeAssignment
from tests.testapp.models import GlobalThing, Node

SCOPED_ACCESS_TREE = {
    "HIERARCHY": [
        {"level": "ROOT"},
        {"level": "REGION", "model": "testapp.Node", "discriminator": {"level": "REGION"}},
        {
            "level": "FACILITY",
            "model": "testapp.Node",
            "parent": "parent",
            "discriminator": {"level": "FACILITY"},
        },
    ]
}


@pytest.fixture
def node_world(settings, db):
    settings.SCOPED_ACCESS = SCOPED_ACCESS_TREE
    north = Node.objects.create(slug="north", level="REGION")
    south = Node.objects.create(slug="south", level="REGION")
    north_hospital = Node.objects.create(slug="north-hospital", level="FACILITY", parent=north)
    south_hospital = Node.objects.create(slug="south-hospital", level="FACILITY", parent=south)
    Node.objects.create(slug="not-a-hierarchy-node", level="OTHER")

    region_user = get_user_model().objects.create(username="region-user")
    facility_user = get_user_model().objects.create(username="facility-user")
    superuser = get_user_model().objects.create(username="root", is_superuser=True)
    inactive_user = get_user_model().objects.create(username="inactive", is_active=False)
    inactive_superuser = get_user_model().objects.create(
        username="inactive-root", is_active=False, is_superuser=True
    )
    role = RoleService.create(by=superuser, name="member")
    ScopeAssignment.objects.grant(user=region_user, role=role, scope=north, by=superuser)
    ScopeAssignment.objects.grant(user=facility_user, role=role, scope=north_hospital, by=superuser)
    ScopeAssignment.objects.grant(user=inactive_user, role=role, scope=north, by=superuser)

    return {
        "region_user": region_user,
        "facility_user": facility_user,
        "superuser": superuser,
        "inactive_user": inactive_user,
        "inactive_superuser": inactive_superuser,
        "north": north,
        "north_hospital": north_hospital,
        "south_hospital": south_hospital,
    }


def _visible_slugs(user):
    return set(engine.visible_resources(user, Node).values_list("slug", flat=True))


def test_region_assignment_sees_region_and_descendant_nodes(node_world):
    assert _visible_slugs(node_world["region_user"]) == {"north", "north-hospital"}


def test_facility_assignment_does_not_gain_upward_visibility(node_world):
    assert _visible_slugs(node_world["facility_user"]) == {"north-hospital"}


def test_superuser_sees_only_nodes_matching_configured_levels(node_world):
    assert _visible_slugs(node_world["superuser"]) == {
        "north",
        "south",
        "north-hospital",
        "south-hospital",
    }


@pytest.mark.parametrize("principal", ["inactive_user", "inactive_superuser"])
def test_inactive_principal_sees_no_hierarchy_nodes(node_world, principal):
    user = node_world[principal]
    assert _visible_slugs(user) == set()
    assert not engine.accessible_nodes(user, "REGION").exists()


@pytest.mark.parametrize("principal", ["inactive_user", "inactive_superuser"])
def test_inactive_principal_sees_no_global_resources(node_world, principal):
    GlobalThing.objects.create(slug="global")
    assert not engine.visible_resources(node_world[principal], GlobalThing).exists()
