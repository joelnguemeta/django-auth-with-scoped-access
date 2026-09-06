# Assignment Lifecycle & Role Management

Django Scoped Access provides a complete, auditable lifecycle state machine for scope assignments. Assignments are **never hard-deleted**—they form an immutable audit trail.

---

## 1. Assignment State Machine

Scope assignments transition through three well-defined states:

```
          ┌───────────────────────────┐
          │          ACTIVE           │
          └───────────┬───▲───────────┘
                      │   │
           suspend()  │   │  reactivate()
                      │   │
          ┌───────────▼───┴───────────┐
          │         SUSPENDED         │
          └───────────┬───────────────┘
                      │
                      │  revoke() [Terminal]
                      ▼
          ┌───────────────────────────┐
          │          REVOKED          │
          └───────────────────────────┘
```

- **ACTIVE**: The assignment is in effect (subject to temporal validity).
- **SUSPENDED**: Temporarily inactive (e.g. during employee leave or security audit). Can be reactivated.
- **REVOKED**: Permanently terminated. Records `revoked_by`, `revoked_at`, and `reason`.

---

## 2. Temporal Validity (`valid_from` / `valid_until`)

An assignment is **effective** at time $t$ if and only if:

$$
\text{effective}(a, t) \iff \begin{cases}
a.\text{status} = \text{ACTIVE} \\
\text{AND } (a.\text{valid\_from is NULL} \lor a.\text{valid\_from} \le t) \\
\text{AND } (a.\text{valid\_until is NULL} \lor t < a.\text{valid\_until})
\end{cases}
$$

> [!IMPORTANT]
> **Read-Time Evaluation**: Temporal validity is computed dynamically at query time in SQL. The system does not depend on background cron jobs to invalidate expired grants.

---

## 3. Managing Assignments via Python API

### Granting an Assignment

```python
from datetime import timedelta
from django.utils import timezone
from scoped_access import ScopeAssignment

# Temporary 30-day assignment
assignment = ScopeAssignment.objects.grant(
    user=doctor,
    role=physician_role,
    scope=maternity_department,
    valid_from=timezone.now(),
    valid_until=timezone.now() + timedelta(days=30),
    by=admin_user,
)
```

### Suspending and Reactivating

```python
# Suspend an assignment (requires manage_assignments)
assignment.suspend(by=manager_user, reason="Temporary leave")

# Reactivate when the user returns (requires manage_assignments and Rule R7 anti-escalation)
assignment.reactivate(by=manager_user, reason="Returned from leave")
```

> [!IMPORTANT]
> **Anti-Escalation on Reactivation (Rule R7)**: Reactivating an assignment restores authority to the assignee. Therefore, `reactivate()` strictly enforces Rule **R7** (`can_assign_role`): the acting manager must possess all permissions contained in the role at the assignment's target scope (or satisfy the configured `GRANTABLE_PERMISSIONS` delegation policy). Suspending or revoking only requires `manage_assignments` authority.


### Revoking an Assignment

```python
# Terminal revocation
assignment.revoke(by=admin_user, reason="Transferred to another facility")
```

---

## 4. Role Management (`RoleService`)

All creation, modification, and deletion of roles must pass through `RoleService`:

```python
from scoped_access import RoleService

# 1. Create a System Role (Global)
admin_role = RoleService.create(
    name="Global Auditor",
    description="Can view all reports across the entire organization",
    permissions=[view_report_perm],
    by=super_admin,
)

# 2. Create a Custom Role (Owned by a Facility)
nurse_role = RoleService.create(
    name="Triage Nurse",
    owner=central_facility,
    permissions=[view_patient_perm, change_vitals_perm],
    by=facility_admin,
)

# 3. Modify Role Permissions
RoleService.grant_permissions(nurse_role, add_triage_note_perm, by=facility_admin)
RoleService.revoke_permissions(nurse_role, change_vitals_perm, by=facility_admin)

# 4. Delete a Role
RoleService.delete(nurse_role, by=facility_admin)
```

---

## 5. Lifecycle Signals

Django Scoped Access emits standard Django signals for all lifecycle operations, allowing your application to attach audit logging, notifications, or external integrations:

```python
# audit/receivers.py
from django.dispatch import receiver
from scoped_access import signals

@receiver(signals.assignment_granted)
def log_assignment_grant(sender, assignment, actor, **kwargs):
    AuditLog.objects.create(
        action="GRANT",
        target_user=assignment.user,
        role=assignment.role.name,
        scope=str(assignment.scope),
        performed_by=actor,
    )

@receiver(signals.assignment_revoked)
def log_assignment_revocation(sender, assignment, actor, reason, **kwargs):
    AuditLog.objects.create(
        action="REVOKE",
        target_user=assignment.user,
        role=assignment.role.name,
        scope=str(assignment.scope),
        performed_by=actor,
        reason=reason,
    )

@receiver(signals.role_permissions_changed)
def log_permission_change(sender, role, added, removed, actor, **kwargs):
    AuditLog.objects.create(
        action="ROLE_PERMS_CHANGED",
        role=role.name,
        details={"added": added, "removed": removed},
        performed_by=actor,
    )
```

Lifecycle transitions and role permission changes are executed inside database
transactions. If a signal receiver raises an exception, the library re-raises
it and rolls back the authorization mutation. SQL audit rows written by earlier
receivers on the same database connection roll back with the mutation.

Request-local authorization caches are invalidated before signals are emitted.
Receivers that call `engine.has_perm()` or `engine.user_permissions()` therefore
see the pending authority change while the transaction is open, and the cache is
refreshed from the database after commit or rollback.

For external side effects such as webhooks, message queues, or third-party audit
sinks, prefer `transaction.on_commit()` or a transactional outbox with idempotent
consumers. A network call made directly inside a receiver cannot be rolled back
by the database if a later receiver fails.
