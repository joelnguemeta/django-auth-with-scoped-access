"""Backend-aware atomic primitives for ReAuth token consumption."""

from __future__ import annotations

from django.core.cache import DEFAULT_CACHE_ALIAS, cache, caches

CONSUMED_PREFIX = "scoped_access:reauth:consumed:"
_UNSUPPORTED = object()
_GETDEL_LUA = "local v=redis.call('GET',KEYS[1]); if v then redis.call('DEL',KEYS[1]); end; return v"


def _getdel_or_lua(client, key):
    getdel = getattr(client, "getdel", None)
    if getdel is not None:
        try:
            return getdel(key)
        except Exception as exc:
            # redis-py exposes GETDEL even when the server predates Redis 6.2.
            # Only that server capability error should trigger the Lua path.
            if type(exc).__name__ != "ResponseError":
                raise
    return client.eval(_GETDEL_LUA, 1, key)


def _redis_atomic_pop(key: str):
    """Return and delete a Redis value atomically, or _UNSUPPORTED."""
    backend = caches[DEFAULT_CACHE_ALIAS]
    module = type(backend).__module__

    if module == "django.core.cache.backends.redis":
        safe_key = backend.make_and_validate_key(key)
        internal = backend._cache
        client = internal.get_client(safe_key, write=True)
        raw = _getdel_or_lua(client, safe_key)
        return None if raw is None else internal._serializer.loads(raw)

    if module.startswith("django_redis.cache"):
        internal = backend.client
        safe_key = internal.make_key(key, version=backend.version)
        client = internal.get_client(key=safe_key, write=True)
        raw = _getdel_or_lua(client, safe_key)
        return None if raw is None else internal.decode(raw)

    return _UNSUPPORTED


def atomic_pop(key: str, observed_value, *, token: str, timeout: int):
    """Atomically elect one consumer and return the token payload once."""
    redis_value = _redis_atomic_pop(key)
    if redis_value is not _UNSUPPORTED:
        return redis_value

    # BaseCache.add() is the portable compare-and-set primitive. The claim is
    # retained for the token's physical lifetime, so a deleted/evicted token
    # cannot be accepted again by another concurrent request.
    claim_key = f"{CONSUMED_PREFIX}{token}"
    if not cache.add(claim_key, True, timeout=timeout):
        return None
    if not cache.delete(key):
        return None
    return observed_value
