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
# Check global / flat permission
user.has_perm("helpdesk.view_ticket")

# Check object-level scoped permission
ticket = Ticket.objects.get(pk=101)
user.has_perm("helpdesk.change_ticket", ticket)

# Get all effective permissions covering an object
user.get_all_permissions(ticket)
```

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
    # Filter queryset at database level by user scope
    tickets = Ticket.objects.filter(
        engine.scope_filter_q(request.user, Ticket)
    )
    return render(request, "helpdesk/ticket_list.html", {"tickets": tickets})
```

### Class-Based Views (CBVs)

```python
from django.contrib.auth.mixins import LoginRequiredMixin, PermissionRequiredMixin
from django.views.generic import ListView
from helpdesk.models import Ticket
from scoped_access import engine

class ScopedTicketListView(LoginRequiredMixin, ListView):
    model = Ticket
    template_name = "helpdesk/ticket_list.html"
    context_object_name = "tickets"

    def get_queryset(self):
        return Ticket.objects.filter(
            engine.scope_filter_q(self.request.user, Ticket)
        )
```

---

## 3. Using in Django Templates

In Django templates, the standard `perms` context variable evaluates permissions:

```html
{% if perms.helpdesk.add_ticket %}
    <a href="{% url 'ticket-create' %}" class="btn btn-primary">Create Ticket</a>
{% endif %}
```

---

## 4. Performance & Per-Request Caching

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

`ScopedAccessCacheMiddleware` uses Python `contextvars` to memoize assignment and permission lookups for the duration of the current request. When assignments are granted or revoked during the request, the cache is automatically invalidated in-place.
