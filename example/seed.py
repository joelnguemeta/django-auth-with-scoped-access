"""Run from the example/ directory:

    python manage.py shell < seed.py

Creates two organizations, three teams, tickets, roles and assignments
that demonstrate RBAC + scoped access + ReAuth. Rerunning keeps existing
users, passwords, and assignment history.
"""

import os
import secrets

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django

django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission
from django.contrib.contenttypes.models import ContentType
from helpdesk.models import Organization, Team, Ticket

from scoped_access import RoleService
from scoped_access.models import AssignmentStatus, Role, ScopeAssignment

User = get_user_model()


def seed_user(username, *, superuser=False):
    user = User.objects.filter(username=username).first()
    if user is not None:
        return user, "existing password unchanged"
    password = secrets.token_urlsafe(18)
    if superuser:
        user = User.objects.create_superuser(username, password=password)
    else:
        user = User.objects.create_user(username, password=password)
    return user, password


def seed_role(name, *, owner=None, permissions=()):
    if owner is None:
        role = Role.objects.filter(name=name, owner_id__isnull=True).first()
    else:
        role = Role.objects.filter(
            name=name,
            owner_ct=ContentType.objects.get_for_model(owner),
            owner_id=str(owner.pk),
            owner_level="ORGANIZATION",
        ).first()
    if role is None:
        role = RoleService.create(by=superadmin, name=name, owner=owner)
    missing = [permission for permission in permissions if not role.permissions.filter(pk=permission.pk).exists()]
    if missing:
        role.grant_permissions(*missing, by=superadmin)
    return role


def seed_assignment(user, role, scope):
    if not ScopeAssignment.objects.filter(
        user=user,
        role=role,
        scope_ct=ContentType.objects.get_for_model(scope),
        scope_id=str(scope.pk),
        status__in=[AssignmentStatus.ACTIVE, AssignmentStatus.SUSPENDED],
    ).exists():
        ScopeAssignment.objects.grant(user=user, role=role, scope=scope, by=superadmin)


superadmin, superadmin_password = seed_user("superadmin", superuser=True)
if not superadmin.is_active or not superadmin.is_superuser:
    raise RuntimeError("The existing superadmin account must be an active superuser to seed assignments.")

# ---------------------------------------------------------------------------
# Hierarchy nodes
# ---------------------------------------------------------------------------
org_a, _ = Organization.objects.get_or_create(name="Acme Corp", defaults={"plan": "pro"})
org_b, _ = Organization.objects.get_or_create(name="Globex", defaults={"plan": "free"})

team_a1, _ = Team.objects.get_or_create(organization=org_a, name="Frontend")
team_a2, _ = Team.objects.get_or_create(organization=org_a, name="Backend")
team_b1, _ = Team.objects.get_or_create(organization=org_b, name="Support")

# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------
Ticket.objects.get_or_create(team=team_a1, title="Fix login button", defaults={"body": "It's broken on Safari."})
Ticket.objects.get_or_create(team=team_a1, title="Add dark mode")
Ticket.objects.get_or_create(team=team_a2, title="Optimise DB queries")
Ticket.objects.get_or_create(team=team_b1, title="Customer can't log in")

# ---------------------------------------------------------------------------
# Permissions (Django native)
# ---------------------------------------------------------------------------
view_ticket = Permission.objects.get(content_type__app_label="helpdesk", codename="view_ticket")
add_ticket = Permission.objects.get(content_type__app_label="helpdesk", codename="add_ticket")
change_ticket = Permission.objects.get(content_type__app_label="helpdesk", codename="change_ticket")
delete_ticket = Permission.objects.get(content_type__app_label="helpdesk", codename="delete_ticket")

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
# System role — owner=None means system-wide
viewer = seed_role("viewer", permissions=[view_ticket])

# System role with full CRUD
agent = seed_role("agent", permissions=[view_ticket, add_ticket, change_ticket, delete_ticket])

# Custom role owned by Org A — visible only inside Acme Corp
triage = seed_role("triage-agent", owner=org_a, permissions=[view_ticket, add_ticket])

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
alice, alice_password = seed_user("alice")  # admin of Org A
bob, bob_password = seed_user("bob")  # agent of Team A1 only
carol, carol_password = seed_user("carol")  # viewer across both orgs

# Alice → agent role scoped to Org A (covers both teams)
seed_assignment(alice, agent, org_a)

# Bob → agent role scoped to Team A1 only
seed_assignment(bob, agent, team_a1)

# Carol → viewer at Org A + Org B
seed_assignment(carol, viewer, org_a)
seed_assignment(carol, viewer, org_b)

print("Seed complete.")
print()
print("Users (username / password):")
print(f"  alice / {alice_password} — agent on all of Acme Corp (ORGANIZATION level)")
print(f"  bob   / {bob_password} — agent on Frontend team only (TEAM level)")
print(f"  carol / {carol_password} — viewer on both Acme Corp and Globex")
print(f"  superadmin / {superadmin_password} — bootstrap superuser")
print()
print("Endpoints (run: python manage.py runserver):")
print("  GET  /api/tickets/          — filtered by caller's scope")
print("  POST /api/tickets/          — requires add_ticket in the target team's scope")
print("  DEL  /api/tickets/<id>/     — requires X-ReAuth-Token header")
print('  POST /api/auth/reauth/      — {"password": "..."} → reauth_token')
print("  GET  /api/me/access/        — effective permissions + assignments")
