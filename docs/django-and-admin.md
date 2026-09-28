# Standard Django & Admin Integration

Django Scoped Access integrates with standard Django views, forms, templates, and the Django Admin without requiring a custom `User` model.

---

## 1. Authentication Backend

Add `ScopedPermissionBackend` to your `AUTHENTICATION_BACKENDS` setting:

```python
# settings.py
AUTHENTICATION_BACKENDS = [
    "django.contrib.auth.backends.ModelBackend",         # Verifies username/password
    "scoped_access.backends.ScopedPermissionBackend",    # Resolves scoped permissions
]
```

With this backend registered, standard Django permission checks work automatically:

```python
# Object-level scoped check: the permission AND the ticket's scope
ticket = Ticket.objects.get(pk=101)
user.has_perm("helpdesk.change_ticket", ticket)

# All effective permissions covering an object
user.get_all_permissions(ticket)

# Without an object: "held in at least one effective assignment, anywhere"
user.has_perm("helpdesk.view_ticket")
```

!!! warning "`has_perm()` without an object is not a scope check"
    Without `obj`, the answer is `True` if **any** effective assignment grants the permission, whatever its scope. Use it for navigation hints ("show the Tickets menu"), never to authorize access to a specific object or to build a list. Pass the object, or filter the queryset as shown below.

---

## 2. Using in Standard Django Views

### Function-Based Views

```python
from django.contrib.auth.decorators import login_required
from django.core.exceptions import PermissionDenied
from django.shortcuts import get_object_or_404, render
from helpdesk.models import Ticket
from scoped_access import engine

@login_required
def ticket_detail(request, pk):
    ticket = get_object_or_404(Ticket, pk=pk)

    # Check permission and scope
    if not request.user.has_perm("helpdesk.view_ticket", ticket):
        raise PermissionDenied("You do not have access to this ticket.")

    return render(request, "helpdesk/ticket_detail.html", {"ticket": ticket})

@login_required
def ticket_list(request):
    # SQL-filtered: only tickets in scopes where the user holds view_ticket
    tickets = engine.visible_resources(request.user, Ticket, permission="helpdesk.view_ticket")
    return render(request, "helpdesk/ticket_list.html", {"tickets": tickets})
```

Always pass `permission=`. Without it, the filter keeps every resource the user's assignments **cover**, whatever permissions their roles hold there.

### Class-Based Views (CBVs)

```python
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from helpdesk.models import Ticket
from scoped_access import engine

class ScopedTicketListView(LoginRequiredMixin, ListView):
    model = Ticket
    template_name = "helpdesk/ticket_list.html"
    context_object_name = "tickets"

    def get_queryset(self):
        return engine.visible_resources(
            self.request.user, Ticket, permission="helpdesk.view_ticket"
        ).select_related("team")
```

`engine.scope_filter_q(user, Ticket, permission=...)` returns the underlying `Q` if you need to combine it with other filters. Add `.distinct()` when the anchor crosses a multi-valued relation.

---

## 3. Using in Django Templates

In Django templates, the standard `perms` context variable calls `has_perm()` **without an object**, so it answers "held somewhere" (see the warning above). It is fine for showing or hiding UI elements; the view must still check the object or filter the queryset:

```html
{% if perms.helpdesk.add_ticket %}
    <a href="{% url 'ticket-create' %}" class="btn btn-primary">Create Ticket</a>
{% endif %}
```

---

## 4. Django Admin

The backend answers the admin's permission checks, so staff users with scoped roles can log into the admin. The stock `ModelAdmin`, however, **is not scope-aware**: change lists and foreign-key dropdowns show every row, and change/delete permissions are checked without the object. A `change_ticket` held in Team A would then allow editing Team B's tickets.

Use `ScopedModelAdmin` for every registered resource:

```python
# helpdesk/admin.py
from django.contrib import admin
from helpdesk.models import Ticket
from scoped_access.admin import ScopedModelAdmin


@admin.register(Ticket)
class TicketAdmin(ScopedModelAdmin):
    list_display = ["title", "team", "is_closed"]
    search_fields = ["title"]
```

| Admin behavior | `ScopedModelAdmin` |
|---|---|
| Change list, search, detail pages | Only rows where the user holds `view_*` (SQL-filtered). Other rows are reported as missing. |
| View / change / delete checks | Evaluated **on the object**: the permission must hold in that object's scope. |
| Saving (add, edit, `list_editable`) | Write guard: `add_*`/`change_*` must hold at the **target** scope, and on edit at the stored one too. Otherwise `403`. |
| "Delete selected" action | Refused (`403`) if any selected object is outside the user's `delete_*` scope. |
| Foreign-key dropdowns | Hierarchy nodes: only nodes where the user may add or change this model. Registered resources: only rows they may view. Other models: untouched. |

Two rules follow from the specification:

- **No permission implies another.** Holding `change_ticket` without `view_ticket` in a scope does not reveal that scope's tickets in the admin. Put `view_*` in roles meant for admin editors.
- **Inlines are not scoped.** Give inline models their own `ScopedModelAdmin` and edit them there, or scope your `InlineModelAdmin` subclasses by hand.

Override the provided methods (`get_queryset`, `save_model`, `formfield_for_foreignkey`, …) only by calling `super()`, or the corresponding guard is lost.

!!! note "Keep business permissions out of Django groups"
    Permissions granted through `user.user_permissions` or groups are resolved by `ModelBackend`. They are global and unscoped. Grant business permissions only through roles and assignments, so every one of them carries a scope.

---

## 5. Performance & Per-Request Caching

During a typical web request, permission checks on navigation menus, object buttons, and table rows may execute dozens of times.

To avoid duplicate database queries, enable the per-request caching middleware:

```python
# settings.py
MIDDLEWARE = [
    ...
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    # Place after AuthenticationMiddleware
    "scoped_access.cache.ScopedAccessCacheMiddleware",
]
```

`ScopedAccessCacheMiddleware` uses Python `contextvars` to memoize assignment and permission lookups for the duration of the current request. Grants, suspensions, reactivations, revocations and role permission changes made during the request invalidate the cache in place, so a revocation takes effect on the very next check. The cache never outlives the request.
