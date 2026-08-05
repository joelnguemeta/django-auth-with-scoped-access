"""Per-request memoization of effective assignments (SPEC §11).

The revocation guarantee forbids caching assignment data across requests
unless invalidated by the §9 events — so the store is a contextvar scoped to
one request, and the models' lifecycle APIs invalidate it in-place (a grant
or revoke is visible to checks later in the same request).

Enable with the middleware (optional — without it every check hits the DB,
which is correct, just slower)::

    MIDDLEWARE = [
        ...
        "scoped_access.cache.ScopedAccessCacheMiddleware",
    ]
"""

from __future__ import annotations

import contextvars
from contextlib import contextmanager

_store: contextvars.ContextVar[dict | None] = contextvars.ContextVar("scoped_access_request_cache", default=None)


@contextmanager
def request_cache():
    """Activate a fresh memoization store for the duration of the block."""
    token = _store.set({})
    try:
        yield
    finally:
        _store.reset(token)


def get_store() -> dict | None:
    return _store.get()


def invalidate_user(user_pk) -> None:
    store = _store.get()
    if store is not None:
        store.pop(("assignments", str(user_pk)), None)


def invalidate_all() -> None:
    """Role permission sets changed: every user's cache is stale."""
    store = _store.get()
    if store is not None:
        store.clear()


class ScopedAccessCacheMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        with request_cache():
            return self.get_response(request)
