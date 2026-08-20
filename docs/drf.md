# Django REST Framework (DRF) Integration

Django Scoped Access provides a complete set of permissions, mixins, and views designed for Django REST Framework.

---

## 1. Quick Overview of DRF Components

| Component | Type | Purpose |
|---|---|---|
| `ScopedModelPermission` | Permission | Maps HTTP methods (`GET` → `view_*`, `POST` → `add_*`, `PUT/PATCH` → `change_*`, `DELETE` → `delete_*`). Read access requires explicit `view_*`. |
| `ScopeObjectPermission` | Permission | Object-level permission checking if the target resource's anchor is covered by the caller's scope. |
| `ScopeQuerySetMixin` | ViewSet Mixin | Filters collection querysets in SQL so `list` actions only return resources inside the caller's scope. |
| `ScopeWriteGuardMixin` | ViewSet Mixin | Write-guard validating that the **target** (new) scope on `create` or `update` (moving an object) is covered by the caller. |
| `RequireReAuth` | Permission | Step-up gate requiring a valid `X-ReAuth-Token` header. |
| `MeAccessView` | APIView | Returns the authenticated principal's effective permissions and assignments. |
| `ReAuthView` | APIView | Exchanges user credentials (e.g. password) for a single-use ReAuth token. |

---

## 2. Setting Up ViewSets

To protect a standard `ModelViewSet`, combine the mixins and permission classes:

```python
# views.py
from rest_framework.viewsets import ModelViewSet
from helpdesk.models import Ticket
from helpdesk.serializers import TicketSerializer
from scoped_access.drf import (
    RequireReAuth,
    ScopedModelPermission,
    ScopeObjectPermission,
    ScopeQuerySetMixin,
    ScopeWriteGuardMixin,
)

class TicketViewSet(ScopeWriteGuardMixin, ScopeQuerySetMixin, ModelViewSet):
    queryset = Ticket.objects.select_related("team__organization")
    serializer_class = TicketSerializer
    permission_classes = [ScopedModelPermission, ScopeObjectPermission]

    def get_permissions(self):
        permissions = super().get_permissions()
        if self.action == "destroy":
            # Gated with Step-Up Re-Authentication
            permissions.append(RequireReAuth())
        return permissions
```

> [!WARNING]
> **Best Practice against IDOR**:  
> Always include `ScopeObjectPermission` alongside `ScopeQuerySetMixin`. `ScopeQuerySetMixin` filters the list view, while `ScopeObjectPermission` enforces scope checks on detail endpoints (`retrieve`, `update`, `destroy`).

---

## 3. The Write Guard (`ScopeWriteGuardMixin`)

A common vulnerability in multi-tenant REST APIs is the **Scope Injection / Scope Hijacking** vulnerability:
- A user with permission to create tickets in *Team A* attempts to `POST` a payload with `{"team": "Team B"}`.
- A user with permission to edit a ticket in *Team A* attempts to `PATCH` the ticket with `{"team": "Team B"}` to move it to a team they do not control.

`ScopeWriteGuardMixin` prevents this by constructing a transient model instance with the deserialized payload and evaluating `engine.user_covers()` against the **new target anchor** before persisting the write.

---

## 4. Introspection Endpoint (`GET /me/access/`)

Expose the caller's effective access tree for frontend SPAs (React, Vue, mobile apps):

```python
# urls.py
from django.urls import path
from scoped_access.drf import MeAccessView

urlpatterns = [
    path("api/me/access/", MeAccessView.as_view(), name="me-access"),
]
```

### Example JSON Response:

```json
{
  "principal": {
    "id": "42",
    "superuser": false,
    "active": true
  },
  "permissions": [
    "helpdesk.add_ticket",
    "helpdesk.change_ticket",
    "helpdesk.view_ticket"
  ],
  "assignments": [
    {
      "role": {
        "id": "7",
        "name": "Support Agent",
        "system": true
      },
      "level": "TEAM",
      "scope": {
        "id": "12",
        "label": "Customer Support — Acme Corp"
      },
      "status": "ACTIVE",
      "valid_until": null,
      "permissions": [
        "helpdesk.add_ticket",
        "helpdesk.change_ticket",
        "helpdesk.view_ticket"
      ]
    }
  ]
}
```
