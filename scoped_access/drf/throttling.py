"""Dedicated throttling for credential-verification endpoints."""

from __future__ import annotations

from rest_framework.throttling import UserRateThrottle

from ..conf import get_config


class ReAuthRateThrottle(UserRateThrottle):
    """Per-user ReAuth throttle with a secure library default."""

    scope = "scoped_access_reauth"

    def get_rate(self):
        return get_config().reauth["RATE"]
