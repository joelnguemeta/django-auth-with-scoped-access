"""Spawn-safe Redis consumer, deliberately independent of the parent process."""


def consume(token, user_id, fresh, barrier, queue):
    import django

    django.setup()
    from types import SimpleNamespace

    from django.core.cache import cache

    from scoped_access.reauth import ReAuthService
    from scoped_access.reauth.service import TOKEN_PREFIX

    original_get = cache.get

    def synchronized_get(key, *args, **kwargs):
        value = original_get(key, *args, **kwargs)
        if key == f"{TOKEN_PREFIX}{token}":
            barrier.wait(timeout=15)
        return value

    cache.get = synchronized_get
    barrier.wait(timeout=15)
    queue.put(ReAuthService.consume(token, SimpleNamespace(pk=user_id, is_active=True), fresh=fresh))
