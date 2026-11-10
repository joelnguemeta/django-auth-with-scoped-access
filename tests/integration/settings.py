"""Settings for the dedicated PostgreSQL and Redis integration job."""

import os

from tests.settings import *  # noqa: F403

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "postgres",
        "USER": os.environ.get("SCOPED_TEST_PGUSER", "postgres"),
        "HOST": os.environ.get("SCOPED_TEST_PGHOST", "127.0.0.1"),
        "PORT": os.environ.get("SCOPED_TEST_PGPORT", "5432"),
    }
}
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.redis.RedisCache",
        "LOCATION": os.environ.get("SCOPED_TEST_REDIS_URL", "redis://127.0.0.1:6379/15"),
        "KEY_PREFIX": "scoped-access-integration",
    }
}
SCOPED_ACCESS = {"REAUTH": {"ENABLED": True, "TTL": 300, "MODE": os.environ.get("SCOPED_TEST_REAUTH_MODE", "window")}}
