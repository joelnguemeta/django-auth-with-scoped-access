# Configuration Reference

Django Scoped Access is configured via the `SCOPED_ACCESS` dictionary in your `settings.py` along with a few optional top-level settings for swappable models.

---

## Complete Configuration Example

```python
# settings.py

SCOPED_ACCESS = {
    # 1. Ordered Hierarchy
    "HIERARCHY": [
        {"level": "GLOBAL"},
        {"level": "REGION", "model": "geo.Region"},
        {"level": "DISTRICT", "model": "geo.District", "parent": "region"},
        {"level": "FACILITY", "model": "org.Facility", "parent": "district"},
    ],

    # 2. Levels allowed to own custom roles
    "ROLE_OWNER_LEVELS": ["FACILITY"],

    # 3. Delegation policy ("self" | "any" | list[str] | callable)
    "GRANTABLE_PERMISSIONS": "self",

    # 4. Fail closed when a resource model was not registered
    "STRICT_REGISTRATION": True,

    # 5. Step-Up Re-Authentication settings
    "REAUTH": {
        "ENABLED": True,
        "TTL": 300,  # Token validity in seconds (default: 300)
    },
}

# Optional swappable models (set before initial migration)
SCOPED_ACCESS_ROLE_MODEL = "scoped_access.Role"
SCOPED_ACCESS_ASSIGNMENT_MODEL = "scoped_access.ScopeAssignment"
```

---

## Settings Breakdown

### `HIERARCHY` (Required)
**Type**: `list[dict]`  
**Default**: `[]` (degrades to standard flat RBAC)

An ordered list of hierarchy level declarations from highest rank (0) to lowest rank.

#### Level Dictionary Keys:

| Key | Type | Required | Description |
|---|---|:---:|---|
| `level` | `str` | Yes | Unique uppercase identifier for the level (e.g., `"NATIONAL"`, `"REGION"`, `"TEAM"`). |
| `model` | `str` | No | Model label (`"app_label.ModelName"`). If omitted, this level is treated as a **root level** (rank 0). |
| `parent` | `str` | Cond. | ORM accessor to reach the parent modeled level instance (e.g., `"organization"`, `"region"`, `"department__facility"`). Required for all modeled levels except the first modeled level. |
| `discriminator` | `dict` | No | Query filter kwargs when multiple hierarchy levels share a single database table (e.g. `{"type": "FACILITY"}`). |

#### Example: Single-Model Hierarchy with Discriminator
```python
SCOPED_ACCESS = {
    "HIERARCHY": [
        {"level": "COMPANY", "model": "org.OrgUnit", "discriminator": {"unit_type": "COMPANY"}},
        {"level": "BRANCH", "model": "org.OrgUnit", "parent": "parent_unit", "discriminator": {"unit_type": "BRANCH"}},
    ]
}
```

---

### `ROLE_OWNER_LEVELS` (Optional)
**Type**: `list[str]`  
**Default**: `[]`

A subset of modeled hierarchy levels that are permitted to own custom roles.
- Levels in this list allow local tenant administrators to define custom roles restricted to their subtree.
- Cannot contain the root level (system roles have `owner = None`).

---

### `GRANTABLE_PERMISSIONS` (Optional)
**Type**: `"self"` | `"any"` | `list[str]` | `set[str]` | `callable`  
**Default**: `"self"`

Defines the anti-escalation policy when creating or modifying roles:

- `"self"` (Recommended): An actor can only grant permissions they hold effectively at the role's owner scope.
- `"any"`: Any permission in the system can be assigned (disables anti-escalation).
- `list[str]`: An explicit allowlist of permission codenames (e.g. `["helpdesk.view_ticket", "helpdesk.change_ticket"]`).
- `callable`: A custom function with signature `fn(actor, role, permission, at=None) -> bool`.

---

### `REAUTH` (Optional)
**Type**: `dict`  
**Default**: `{"ENABLED": False, "TTL": 300}`

Configuration for the Step-Up Re-Authentication subsystem:

| Key | Type | Default | Description |
|---|---|:---:|---|
| `ENABLED` | `bool` | `False` | Whether step-up re-authentication checks are enforced. |
| `TTL` | `int` | `300` | Lifetime of a single-use re-authentication token in seconds. |

---

### `STRICT_REGISTRATION` (Optional)
**Type**: `bool`
**Default**: `False`

When enabled, models that are neither hierarchy nodes nor registered resources fail closed for non-superusers. Declare intentionally global models explicitly:

```python
from scoped_access import register, register_global

register(Ticket, anchor="team")
register_global(Country)
```

`manage.py check` reports `scoped_access.E012` for unregistered models in the host applications inferred from the hierarchy and resource registry.

---

### Swappable Model Settings (Optional)

You can customize the concrete `Role` or `ScopeAssignment` models by specifying swappable settings before running migrations:

```python
SCOPED_ACCESS_ROLE_MODEL = "custom_auth.MyCustomRole"
SCOPED_ACCESS_ASSIGNMENT_MODEL = "custom_auth.MyCustomAssignment"
```

See [Swappable Models](swappable-models.md) for implementation details.

---

## System Checks Validation

Django Scoped Access automatically validates your configuration during `manage.py check` or server startup:

| Code | Severity | Description |
|---|:---:|---|
| `scoped_access.E001` | Error | Duplicate level names found in `HIERARCHY`. |
| `scoped_access.E002` | Error | More than one root level, or root level is not at index 0. |
| `scoped_access.E003` | Error | Modeled level is missing a required `parent` accessor. |
| `scoped_access.E004` | Error | `ROLE_OWNER_LEVELS` references a non-modeled or unknown level. |
| `scoped_access.E005` | Error | Invalid `GRANTABLE_PERMISSIONS` setting value. |
| `scoped_access.E006` | Error | Configured model label could not be loaded. |
| `scoped_access.E007` | Error | Invalid ORM relationship path in `parent` accessor. |
| `scoped_access.E008` | Error | Invalid ORM relationship path in registered resource `anchor`. |
| `scoped_access.E009` | Error | Invalid `REAUTH.ENABLED` setting. |
| `scoped_access.E010` | Error | `REAUTH.TTL` must be a positive integer. |
| `scoped_access.E011` | Error | `STRICT_REGISTRATION` is not a boolean. |
| `scoped_access.E012` | Error | Strict mode found an unregistered host model. |
| `scoped_access.W001` | Warning | `REAUTH` is enabled but the default Django cache is not shared (`LocMemCache`/`DummyCache`). |
