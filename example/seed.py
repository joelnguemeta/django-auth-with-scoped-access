"""
Run from the example/ directory:

    python manage.py shell < seed.py

Creates two organizations, two teams each, tickets, roles and assignments
that demonstrate RBAC + scoped access + ReAuth.
"""
import os
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "config.settings")

import django
django.setup()

from django.contrib.auth import get_user_model
from django.contrib.auth.models import Permission

from scoped_access.models import Role, ScopeAssignment
from helpdesk.models import Organization, Team, Ticket

User = get_user_model()

# ---------------------------------------------------------------------------
# Wipe previous seed data
# ---------------------------------------------------------------------------
User.objects.filter(username__in=["alice", "bob", "carol", "superadmin"]).delete()
Organization.objects.all().delete()

# ---------------------------------------------------------------------------
# Hierarchy nodes
# ---------------------------------------------------------------------------
org_a = Organization.objects.create(name="Acme Corp", plan="pro")
org_b = Organization.objects.create(name="Globex", plan="free")

team_a1 = Team.objects.create(organization=org_a, name="Frontend")
team_a2 = Team.objects.create(organization=org_a, name="Backend")
team_b1 = Team.objects.create(organization=org_b, name="Support")

# ---------------------------------------------------------------------------
# Tickets
# ---------------------------------------------------------------------------
Ticket.objects.create(team=team_a1, title="Fix login button", body="It's broken on Safari.")
Ticket.objects.create(team=team_a1, title="Add dark mode")
Ticket.objects.create(team=team_a2, title="Optimise DB queries")
Ticket.objects.create(team=team_b1, title="Customer can't log in")

# ---------------------------------------------------------------------------
# Permissions (Django native)
# ---------------------------------------------------------------------------
view_ticket   = Permission.objects.get(codename="view_ticket")
add_ticket    = Permission.objects.get(codename="add_ticket")
change_ticket = Permission.objects.get(codename="change_ticket")
delete_ticket = Permission.objects.get(codename="delete_ticket")

# ---------------------------------------------------------------------------
# Roles
# ---------------------------------------------------------------------------
# System role — owner=None means system-wide
viewer = Role.objects.create(name="viewer")
viewer.grant_permissions(view_ticket)

# System role with full CRUD
agent = Role.objects.create(name="agent")
agent.grant_permissions(view_ticket, add_ticket, change_ticket)

# Custom role owned by Org A — visible only inside Acme Corp
triage = Role.objects.create(name="triage-agent", owner=org_a)
triage.grant_permissions(view_ticket, add_ticket)

# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
alice = User.objects.create_user("alice", password="alice123")   # admin of Org A
bob   = User.objects.create_user("bob",   password="bob123")     # agent of Team A1 only
carol = User.objects.create_user("carol", password="carol123")   # viewer across both orgs

# Alice → agent role scoped to Org A (covers both teams)
ScopeAssignment.objects.grant(user=alice, role=agent, scope=org_a, by=alice)

# Bob → agent role scoped to Team A1 only
ScopeAssignment.objects.grant(user=bob, role=agent, scope=team_a1, by=alice)

# Carol → viewer at Org A + Org B
ScopeAssignment.objects.grant(user=carol, role=viewer, scope=org_a, by=alice)
ScopeAssignment.objects.grant(user=carol, role=viewer, scope=org_b, by=alice)

print("Seed complete.")
print()
print("Users (username / password):")
print("  alice / alice123  — agent on all of Acme Corp (ORGANIZATION level)")
print("  bob   / bob123    — agent on Frontend team only (TEAM level)")
print("  carol / carol123  — viewer on both Acme Corp and Globex")
print()
print("Endpoints (run: python manage.py runserver):")
print("  GET  /api/tickets/          — filtered by caller's scope")
print("  POST /api/tickets/          — requires add_ticket in the target team's scope")
print("  DEL  /api/tickets/<id>/     — requires X-ReAuth-Token header")
print("  POST /api/auth/reauth/      — {\"password\": \"...\"} → reauth_token")
print("  GET  /api/me/access/        — effective permissions + assignments")
