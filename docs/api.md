# Python API Reference

The public, framework-agnostic API. Everything here works without DRF installed. Every engine function accepts an optional `at=` datetime to evaluate at another instant (default: now). Explicit-clock calls bypass the per-request cache.

---

## Registry

```python
from scoped_access import register, register_global
```

| Function | Purpose |
|---|---|
| `register(model, *, anchor)` | Attach a resource model to the hierarchy. `anchor` is the ORM path from the model to a node (`"team"`, `"encounter__facility"`). |
| `register_global(model)` | Declare a model intentionally global: RBAC applies, scope checks are skipped. Required for global models under `STRICT_REGISTRATION`. |

Call both from `AppConfig.ready()`, before the application serves traffic.

---

## Authorization Engine

```python
from scoped_access import engine
```

### Decisions

| Function | Returns |
|---|---|
| `has_perm(user, perm, obj=None)` | `True` if `user` holds `perm` ("app_label.codename") on `obj`. Inactive users are always denied, and superusers always allowed. Without `obj`, the permission may be held **anywhere** (see [the warning](django-and-admin.md#1-authentication-backend)). |
| `user_permissions(user, obj=None)` | The set of permissions `user` holds on `obj`, or anywhere when `obj` is `None`. |
| `user_covers(user, obj)` | Scope-only check: does any effective assignment cover `obj`? The object may be unsaved, which makes it the building block of write guards. Combine it with `has_perm()`. |

### Collections (SQL-level)

| Function | Returns |
|---|---|
| `visible_resources(user, model, permission=None)` | A distinct queryset of `model` rows the user may reach. |
| `scope_filter_q(user, model, permission=None)` | The underlying `Q` object, to combine with other filters. |
| `accessible_nodes(user, level_name, permission=None)` | A queryset of hierarchy nodes at `level_name` reachable by the user (for dropdowns, pickers, dashboards). |

!!! warning "Pass `permission=`"
    With `permission`, only assignments whose role contains that permission contribute to the filter. Without it, every covering assignment counts, whatever its role. A `view_ticket` held in Team A must not reveal Team B's tickets because the user holds an unrelated role in Team B.

### Introspection

| Function | Returns |
|---|---|
| `effective_assignments(user)` | The user's assignments that are `ACTIVE` and inside their validity window. |
| `access_summary(user)` | `{"permissions": [...], "assignments": [...]}`, the data behind `GET /me/access/`. |

### Administration Rules

Used by the services below. Call them to decide what to show in an admin UI.

| Function | Rule |
|---|---|
| `role_visible(user, role)` | R1: system roles are visible to everyone, custom roles to users whose scope covers the owner. |
| `role_assignable(role, level_name, node)` | R2: custom roles can only be assigned inside their owner's subtree, never at root. |
| `can_manage_role(actor, role)` | R4: `manage_roles` on the owner, or `manage_global_roles` at root for system roles. |
| `can_grant_permission(actor, role, perm)` | R5: the `GRANTABLE_PERMISSIONS` policy for adding `perm` to `role`. |
| `can_manage_assignment(actor, node=None)` | `manage_assignments` on `node` (or at root when `node` is `None`). |
| `can_assign_role(actor, role, level_name, node=None)` | R7: R2, plus visibility, plus anti-escalation for every permission in the role. |

---

## Roles

```python
from scoped_access import RoleService
```

| Method | Purpose |
|---|---|
| `RoleService.create(*, by, permissions=(), name, description="", owner=None, owner_level=None)` | Create a system role (`owner=None`) or a custom role owned by a node. `owner_level` is only needed when the owner's model maps to several levels. |
| `RoleService.update(role, *, by, **changes)` | Change `name`, `description`, `owner` or `owner_level`. Moving a role to another owner is checked against both owners. |
| `RoleService.grant_permissions(role, *perms, by)` | Add `auth.Permission` objects (anti-escalation enforced). |
| `RoleService.revoke_permissions(role, *perms, by)` | Remove permissions. |
| `RoleService.delete(role, *, by)` | Delete a role. Django raises `ProtectedError` if any assignment references it, **revoked ones included**, since assignments are never deleted. Stop using a role by revoking its assignments. |

---

## Assignments

```python
from scoped_access.models import AssignmentStatus, ScopeAssignment
```

| Call | Purpose |
|---|---|
| `ScopeAssignment.objects.grant(*, user, role, by, scope=None, level=None, valid_from=None, valid_until=None)` | Grant `role` to `user` at `scope`. Use `level=` alone for a root assignment, and neither for flat RBAC. |
| `ScopeAssignment.objects.effective(at=None)` | Queryset filter: `ACTIVE` and inside the validity window. |
| `assignment.suspend(*, by, reason="")` | `ACTIVE → SUSPENDED` |
| `assignment.reactivate(*, by, reason="")` | `SUSPENDED → ACTIVE` (re-checks anti-escalation) |
| `assignment.revoke(*, by, reason="")` | `→ REVOKED` (terminal) |

With a swapped model, use `scoped_access.conf.get_assignment_model()` and `get_role_model()` instead of importing the defaults.

---

## Step-Up Re-Authentication

```python
from scoped_access import ReAuthService, register_verifier
```

| Call | Purpose |
|---|---|
| `ReAuthService.issue(user, *, verifier="password", **credentials)` | Verify a proof and return a single-use token, or `None`. |
| `ReAuthService.consume(token, user)` | Atomically check and burn a token. Returns `bool`. |
| `ReAuthService.invalidate_all_for_user(user)` | Revoke every outstanding token of `user` (done automatically on password change). |
| `register_verifier(verifier)` | Add a proof method (an object with `name` and `verify(user, **credentials) -> bool`). |

---

## Exceptions

All live in `scoped_access.exceptions`.

| Exception | Raised when |
|---|---|
| `ScopedAccessConfigError` | The `SCOPED_ACCESS` setting is malformed. |
| `RoleManagementPermissionError` | The actor may not create, edit or delete this role (R4) or grant a permission (R5). |
| `RoleOwnershipError` | A role owner is not a node of a `ROLE_OWNER_LEVELS` level. |
| `RoleAssignmentError` | The role cannot be assigned there (R2), or the actor would escalate (R7). |
| `AssignmentManagementPermissionError` | The actor lacks `manage_assignments` on the target scope. |
| `AssignmentScopeError` | The scope and level do not match the hierarchy. |
| `InvalidAssignmentTransitionError` | Illegal lifecycle transition (for example reactivating a revoked assignment). |
| `AssignmentDeletionError` | Something tried to hard-delete an assignment. |
| `DirectRoleMutationError`, `DirectRolePermissionMutationError`, `DirectAssignmentMutationError` | A write bypassed the service APIs (`objects.create()`, `update()`, `permissions.add()`, …). |

---

## Django Admin

```python
from scoped_access.admin import ScopedModelAdmin
```

A `ModelAdmin` that filters change lists, checks permissions on the object, guards saves and bulk deletes, and scopes foreign-key dropdowns. See [Django Admin](django-and-admin.md#4-django-admin).

Lifecycle signals are listed in [Lifecycle & Assignments](lifecycle.md#5-lifecycle-signals); the DRF classes in [DRF Integration](drf.md).
