"""The public helpdesk demo should work on a fresh database and on rerun."""

import os
import subprocess
import sys
from pathlib import Path


def test_helpdesk_seed_is_repeatable(tmp_path):
    example = Path(__file__).resolve().parents[1] / "example"
    database = tmp_path / "helpdesk.sqlite3"
    script = """
import django
import runpy
from django.conf import settings
from django.core.management import call_command

django.setup()
settings.DATABASES["default"]["NAME"] = __import__("sys").argv[1]
call_command("migrate", verbosity=0)

from django.contrib.auth import get_user_model
from helpdesk.models import Organization, Team, Ticket
from scoped_access.models import Role, ScopeAssignment

runpy.run_path("seed.py")
first_password = get_user_model().objects.get(username="alice").password
runpy.run_path("seed.py")

assert get_user_model().objects.get(username="alice").password == first_password
assert Organization.objects.count() == 2
assert Team.objects.count() == 3
assert Ticket.objects.count() == 4
assert Role.objects.count() == 3
assert ScopeAssignment.objects.count() == 4
"""
    env = os.environ.copy()
    env["DJANGO_SETTINGS_MODULE"] = "config.settings"
    result = subprocess.run(  # noqa: S603
        [sys.executable, "-c", script, str(database)],
        cwd=example,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
