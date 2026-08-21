"""System checks E001–E010 (SPEC §3): configuration and registry validation."""

from __future__ import annotations

import pytest
from django.test import override_settings

from scoped_access.checks import check_scoped_access_config
from scoped_access.registry import resources
from tests.testapp.models import GlobalThing, Resource


@pytest.fixture(autouse=True)
def clean_registry():
    # Same convention as test_conformance/test_drf: each test owns the registry.
    resources.clear()
    yield
    resources.clear()


def _error_ids(**scoped_access) -> set[str]:
    with override_settings(SCOPED_ACCESS=scoped_access):
        return {e.id for e in check_scoped_access_config(None)}


VALID_HIERARCHY = [
    {"level": "ROOT"},
    {"level": "REGION", "model": "testapp.Node"},
    {"level": "FACILITY", "model": "testapp.Node", "parent": "parent"},
]


def test_valid_config_yields_no_error():
    assert _error_ids(HIERARCHY=VALID_HIERARCHY) == set()


def test_e001_duplicate_level_names():
    assert "scoped_access.E001" in _error_ids(
        HIERARCHY=[{"level": "A", "model": "testapp.Node"}, {"level": "A", "model": "testapp.Node"}]
    )


def test_e002_root_level_not_first():
    assert "scoped_access.E002" in _error_ids(HIERARCHY=[{"level": "A", "model": "testapp.Node"}, {"level": "ROOT"}])


def test_e003_missing_parent_accessor():
    assert "scoped_access.E003" in _error_ids(
        HIERARCHY=[
            {"level": "A", "model": "testapp.Node"},
            {"level": "B", "model": "testapp.Node"},
        ]
    )


def test_e004_owner_level_not_modeled():
    assert "scoped_access.E004" in _error_ids(HIERARCHY=VALID_HIERARCHY, ROLE_OWNER_LEVELS=["NOPE"])


def test_e005_invalid_grantable_permissions():
    assert "scoped_access.E005" in _error_ids(HIERARCHY=VALID_HIERARCHY, GRANTABLE_PERMISSIONS=42)


def test_e006_unloadable_model():
    assert "scoped_access.E006" in _error_ids(HIERARCHY=[{"level": "A", "model": "nosuchapp.Missing"}])


def test_e007_parent_accessor_missing_on_model():
    assert "scoped_access.E007" in _error_ids(
        HIERARCHY=[
            {"level": "A", "model": "testapp.Node"},
            {"level": "B", "model": "testapp.Node", "parent": "nope"},
        ]
    )


def test_e007_accepts_multi_hop_parent():
    # The engine walks multi-hop accessors (_follow / _up_path): the check
    # must accept them too.
    assert "scoped_access.E007" not in _error_ids(
        HIERARCHY=[
            {"level": "A", "model": "testapp.Node"},
            {"level": "B", "model": "testapp.Node", "parent": "parent__parent"},
        ]
    )


def test_e007_rejects_non_relational_segment():
    assert "scoped_access.E007" in _error_ids(
        HIERARCHY=[
            {"level": "A", "model": "testapp.Node"},
            {"level": "B", "model": "testapp.Node", "parent": "slug"},
        ]
    )


def test_e008_invalid_anchor_segment():
    resources.register(Resource, anchor="nope")
    assert "scoped_access.E008" in _error_ids(HIERARCHY=VALID_HIERARCHY)


def test_e008_non_relational_anchor_segment():
    resources.register(GlobalThing, anchor="slug")
    assert "scoped_access.E008" in _error_ids(HIERARCHY=VALID_HIERARCHY)


def test_e008_valid_anchor_passes():
    resources.register(Resource, anchor="anchor__parent")
    assert _error_ids(HIERARCHY=VALID_HIERARCHY) == set()


@pytest.mark.parametrize("reauth", [[], "enabled", 1])
def test_e009_reauth_must_be_a_dictionary(reauth):
    assert "scoped_access.E009" in _error_ids(HIERARCHY=VALID_HIERARCHY, REAUTH=reauth)


@pytest.mark.parametrize("enabled", [0, 1, "true", None])
def test_e009_reauth_enabled_must_be_a_boolean(enabled):
    assert "scoped_access.E009" in _error_ids(
        HIERARCHY=VALID_HIERARCHY,
        REAUTH={"ENABLED": enabled},
    )


@pytest.mark.parametrize("ttl", [True, False, 0, -1, 1.5, "300", None])
def test_e010_reauth_ttl_must_be_a_positive_integer(ttl):
    assert "scoped_access.E010" in _error_ids(
        HIERARCHY=VALID_HIERARCHY,
        REAUTH={"TTL": ttl},
    )


def test_valid_reauth_config_passes(settings):
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": "redis://redis:6379/1",
        }
    }

    assert (
        _error_ids(
            HIERARCHY=VALID_HIERARCHY,
            REAUTH={"ENABLED": True, "TTL": 60},
        )
        == set()
    )


def test_enabled_reauth_warns_on_process_local_cache(settings):
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.locmem.LocMemCache",
        }
    }

    assert "scoped_access.W001" in _error_ids(
        HIERARCHY=VALID_HIERARCHY,
        REAUTH={"ENABLED": True, "TTL": 60},
    )


def test_enabled_reauth_accepts_shared_cache(settings):
    settings.CACHES = {
        "default": {
            "BACKEND": "django.core.cache.backends.redis.RedisCache",
            "LOCATION": "redis://redis:6379/1",
        }
    }

    assert (
        _error_ids(
            HIERARCHY=VALID_HIERARCHY,
            REAUTH={"ENABLED": True, "TTL": 60},
        )
        == set()
    )
