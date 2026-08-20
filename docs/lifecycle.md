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
# Suspend an assignment
assignment.suspend(by=admin_user, reason="Temporary leave")

# Reactivate when the user returns
assignment.reactivate(by=admin_user, reason="Returned from leave")
```

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
