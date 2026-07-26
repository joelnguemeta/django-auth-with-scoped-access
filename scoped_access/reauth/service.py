"""ReAuth token service (SPEC §7): cache-backed, single-use, TTL-limited.

Tokens carry their logical expiry so effectiveness can be evaluated against
an explicit clock (`at`) — same read-time principle as assignments. The cache
timeout is a physical backstop, not the source of truth.
"""

from __future__ import annotations

import secrets
from datetime import timedelta

from django.core.cache import cache
from django.utils import timezone

from .. import signals
from ..conf import get_config
from . import verifiers

TOKEN_PREFIX = "scoped_access:reauth:"
USER_INDEX_PREFIX = "scoped_access:reauth:user:"


class ReAuthService:
    @classmethod
    def issue(cls, user, *, verifier: str = "password", at=None, **credentials) -> str | None:
        """Verify the proof and mint a token; None on failure."""
        verifier_inst = verifiers.get(verifier)
        if not verifier_inst or not verifier_inst.verify(user, **credentials):
            signals.reauth_failed.send(sender=cls, user=user)
            return None

        ttl = int(get_config().reauth["TTL"])
        issued_at = at or timezone.now()
        token = secrets.token_urlsafe(32)
        cache.set(
            f"{TOKEN_PREFIX}{token}",
            {"user_id": str(user.pk), "expires": (issued_at + timedelta(seconds=ttl)).isoformat()},
            timeout=ttl * 2,  # physical backstop; logical expiry checked in consume()
        )
        index_key = f"{USER_INDEX_PREFIX}{user.pk}"
        outstanding = cache.get(index_key) or []
        cache.set(index_key, [*outstanding, token], timeout=ttl * 2)
        signals.reauth_issued.send(sender=cls, user=user)
        return token

    @classmethod
    def consume(cls, token: str | None, user, at=None) -> bool:
        """Atomic check-and-delete. A foreign-principal miss does NOT burn
        the token (SPEC §12.1.1); success and expiry do.
        """
        if not token:
            return False
        key = f"{TOKEN_PREFIX}{token}"
        data = cache.get(key)
        if data is None:
            signals.reauth_failed.send(sender=cls, user=user)
            return False
        if data["user_id"] != str(user.pk):
            signals.reauth_failed.send(sender=cls, user=user)
            return False
        now = at or timezone.now()
        expires = timezone.datetime.fromisoformat(data["expires"])
        if not cache.delete(key):  # single use — burned on success or expiry
            signals.reauth_failed.send(sender=cls, user=user)
            return False
        if now >= expires:
            signals.reauth_failed.send(sender=cls, user=user)
            return False
        signals.reauth_consumed.send(sender=cls, user=user)
        return True

    @classmethod
    def invalidate_all_for_user(cls, user) -> None:
        """SPEC §7.4 — e.g. on credential change."""
        index_key = f"{USER_INDEX_PREFIX}{user.pk}"
        for token in cache.get(index_key) or []:
            cache.delete(f"{TOKEN_PREFIX}{token}")
        cache.delete(index_key)
