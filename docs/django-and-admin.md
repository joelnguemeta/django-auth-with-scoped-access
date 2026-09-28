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

The backend answers the admin's permission checks, so staff users with scoped roles can log into the admin. The admin, however, **does not filter by scope on its own**: change lists and foreign-key dropdowns show every row. Scope the admin explicitly:

```python
# helpdesk/admin.py
from django.contrib import admin
from helpdesk.models import Team, Ticket
from scoped_access import engine


@admin.register(Ticket)
class TicketAdmin(admin.ModelAdmin):
    def get_queryset(self, request):
        # Rows outside the user's scope disappear from lists and return 404 on detail pages.
        return engine.visible_resources(request.user, Ticket, permission="helpdesk.view_ticket")

    # The admin checks change/delete WITHOUT the object: pass it, so the permission must hold in the ticket's scope.
    def has_change_permission(self, request, obj=None):
        return request.user.has_perm("helpdesk.change_ticket", obj) if obj else super().has_change_permission(request)

    def has_delete_permission(self, request, obj=None):
        return request.user.has_perm("helpdesk.delete_ticket", obj) if obj else super().has_delete_permission(request)

    def get_actions(self, request):
        actions = super().get_actions(request)
        actions.pop("delete_selected", None)  # bulk delete checks the permission without the objects
        return actions

    def formfield_for_foreignkey(self, db_field, request, **kwargs):
        if db_field.name == "team":
            # Only offer teams where the user may add tickets: blocks moving a ticket to a foreign scope.
            kwargs["queryset"] = engine.accessible_nodes(request.user, "TEAM", permission="helpdesk.add_ticket")
        return super().formfield_for_foreignkey(db_field, request, **kwargs)
```

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
