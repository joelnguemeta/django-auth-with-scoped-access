# Core Concepts & Architecture

Django Scoped Access is designed around five foundational primitives: **Hierarchies**, **Scopes**, **Anchors**, **Roles**, and **Assignments**.

---

## 1. The Hierarchy

A **Hierarchy** is an ordered list of **Levels**, where index 0 is the top (root or highest rank).

Unlike traditional database schemas where parent-child relationships are hardcoded into permission models, in Django Scoped Access the hierarchy is declared purely in configuration (`settings.py`).

### Hierarchy Levels

- **Root Level (Optional)**: A level without an associated model (e.g. `GLOBAL` or `NATIONAL`). If present, it must be at rank 0. An assignment at the root level covers the entire universe of resources.
- **Modeled Level**: A level backed by a Django model (e.g. `Region`, `District`, `Facility`, `Organization`, `Team`).
- **Parent Accessor**: For any non-root level after the first modeled level, you specify the ORM attribute path used to traverse upwards to its parent node (e.g., `parent="region"`).

```python
SCOPED_ACCESS = {
    "HIERARCHY": [
        {"level": "NATIONAL"},                                                    # Rank 0 (Root)
        {"level": "REGIONAL", "model": "geography.Region"},                       # Rank 1
        {"level": "DISTRICT", "model": "geography.District", "parent": "region"}, # Rank 2
        {"level": "FACILITY", "model": "health.Facility", "parent": "district"},  # Rank 3
    ]
}
```

---

## 2. Nodes & Ancestor Sets

- A **Node** is a specific database row playing the role of a level (e.g., *Region: North*, *Facility: Central Hospital*).
- The **Ancestor Set** of a node $n$ is defined as:

$$\text{ancestor\_set}(n) = \{n\} \cup \text{ancestors}(n)$$

For instance, if *Central Hospital* belongs to *District 4*, which belongs to *Region North*, the ancestor set of *Central Hospital* is:
$$\{\text{Central Hospital}, \text{District 4}, \text{Region North}\}$$

---

## 3. Resource Anchors

A **Resource** is any business object in your application (e.g., `Patient`, `Invoice`, `Ticket`, `MedicalRecord`).

To integrate a resource with the authorization engine, you **register an anchor**: the ORM relationship path from the resource to its hierarchy node.

```python
from scoped_access import register

# Direct anchor: Ticket -> Team
register(Ticket, anchor="team")

# Multi-hop anchor: MedicalRecord -> Encounter -> Facility
register(MedicalRecord, anchor="encounter__facility")
```

### Registered vs. Global Resources

- **Registered Resource**: Attached to a node. Access checks verify both RBAC permissions **and** scope coverage.
- **Unregistered (Global) Resource**: Not attached to any hierarchy node. Scope checks are skipped; standard RBAC permissions apply globally.
- **Null Anchor (Denied Resource)**: If a registered resource's anchor resolves to `None` (e.g., an unassigned ticket), access is **denied by default** to all non-root users.

---

## 4. The Scope Coverage Rule (Normative Core)

An assignment $a$ **covers** a resource $r$ if and only if:

$$
\text{covers}(a, r) \iff \begin{cases}
a.\text{level is the root level} \\
\text{OR} \\
a.\text{node} \in \text{ancestor\_set}(\text{anchor\_node}(r))
\end{cases}
$$

### Fundamental Rules

1. **Inclusive Downward**: A grant at `REGIONAL` covers all districts, facilities, and departments located under that region.
2. **Never Upward**: A grant at `FACILITY` never grants access to region-level or district-level resources.
3. **Identifier Equality**: Node identity comparison uses primary key and `ContentType`, never Python instance memory identity.

---

## 5. System Roles vs. Custom Tenant Roles

Roles are named bundles of Django `auth.Permission` instances.

| Property | System Role | Custom Role (Tenant) |
|---|---|---|
| **Owner** | `owner = None` | Bound to a hierarchy node (`owner = node`) |
| **Visibility (R1)** | Visible globally to all actors | Visible only to actors whose scope covers the owner |
| **Assignability (R2)** | Assignable at any scope level | Assignable **only** within the owner's subtree |
| **Delegated Management (R4)** | Requires `manage_global_roles` (or superuser) | Requires `manage_roles` effective on the owner node |
| **Anti-Escalation (R5)** | Checked against global permissions | Checked against permissions held at owner scope |

### Anti-Escalation Rule (R5)

When a tenant admin creates or edits a custom role, they **cannot delegate permissions they do not possess themselves** at that scope (when `GRANTABLE_PERMISSIONS = "self"`).

This prevents a compromised tenant admin account from creating a backdoor role with global admin or billing privileges.

---

## 6. Zero-Bypass Mutation Architecture

To guarantee auditability and security invariants, direct mutations that bypass the authorization checks or lifecycle state machines are prevented at the ORM level:

```python
# ❌ FAILS: Direct save or create without actor raises DirectAssignmentMutationError
ScopeAssignment.objects.create(user=alice, role=role, ...)

# ❌ FAILS: Hard deletion raises AssignmentDeletionError
assignment.delete()

# ✅ CORRECT: Managed creation via the service API
ScopeAssignment.objects.grant(user=alice, role=role, scope=team, by=admin)

# ✅ CORRECT: Auditable revocation
assignment.revoke(by=admin, reason="Role change")
```

Under the hood, internal `contextvars` tokens (`managed_role_mutation()`, `managed_assignment_mutation()`) ensure that only calls routed through `RoleService` and `ScopeAssignment.objects.grant()` can persist changes.
