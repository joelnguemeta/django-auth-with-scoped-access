"""The public import surface is a tested contract: every documented name
must import, and nothing undocumented leaks from the package root.
"""

from __future__ import annotations

import importlib
import sys

import pytest

import scoped_access


def test_root_all_matches_lazy_map():
    assert sorted(scoped_access.__all__) == sorted(scoped_access._LAZY)


def test_root_names_resolve():
    from scoped_access.reauth import ReAuthService
    from scoped_access.reauth.verifiers import register as register_verifier
    from scoped_access.registry import register

    assert scoped_access.register is register
    assert scoped_access.ReAuthService is ReAuthService
    assert scoped_access.register_verifier is register_verifier
    assert callable(scoped_access.engine.has_perm)
    assert hasattr(scoped_access.signals, "assignment_granted")


def test_root_unknown_attribute_raises():
    with pytest.raises(AttributeError, match="no attribute 'nope'"):
        scoped_access.nope


def test_drf_all_names_resolve():
    drf = importlib.import_module("scoped_access.drf")
    for name in drf.__all__:
        assert getattr(drf, name) is not None


def test_drf_import_without_rest_framework_mentions_extra(monkeypatch):
    monkeypatch.setitem(sys.modules, "rest_framework", None)
    monkeypatch.delitem(sys.modules, "scoped_access.drf", raising=False)
    with pytest.raises(ImportError, match=r"django-scoped-access\[drf\]"):
        importlib.import_module("scoped_access.drf")
