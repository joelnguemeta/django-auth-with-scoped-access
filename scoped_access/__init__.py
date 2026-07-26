"""django-scoped-access — reference implementation of the Scoped Access spec.

See SPEC.md at the repository root. The framework-agnostic public API is
re-exported here — the import map hosts rely on:

    from scoped_access import register           # resource registry (anchors)
    from scoped_access import engine             # authorization engine
    from scoped_access import signals            # §9 lifecycle events
    from scoped_access import ReAuthService      # step-up service
    from scoped_access import register_verifier  # custom step-up proofs

Names resolve lazily (PEP 562): importing the package while Django loads
its apps never touches models or settings. Framework glue lives in its own
subpackage (`scoped_access.drf`, future `scoped_access.ninja`) and is never
re-exported here — the core must import without any web framework installed.
"""

from importlib import import_module

__version__ = "0.1.0.dev0"

__all__ = ["ReAuthService", "engine", "register", "register_verifier", "signals"]

_LAZY = {
    "register": ("scoped_access.registry", "register"),
    "engine": ("scoped_access.engine", None),
    "signals": ("scoped_access.signals", None),
    "ReAuthService": ("scoped_access.reauth", "ReAuthService"),
    "register_verifier": ("scoped_access.reauth", "register_verifier"),
}


def __getattr__(name: str):
    try:
        module_path, attr = _LAZY[name]
    except KeyError:
        raise AttributeError(f"module 'scoped_access' has no attribute '{name}'") from None
    module = import_module(module_path)
    return module if attr is None else getattr(module, attr)
