SECRET_KEY = "test-only"
USE_TZ = True
DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

INSTALLED_APPS = [
    "django.contrib.contenttypes",
    "django.contrib.auth",
    "rest_framework",
    "scoped_access",
    "tests.testapp",
]

ROOT_URLCONF = "tests.urls"

DATABASES = {"default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}}

AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",
    "scoped_access.backends.ScopedPermissionBackend",
]

SCOPED_ACCESS = {}  # overridden per conformance case
