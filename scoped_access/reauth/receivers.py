"""Credential-change hooks for automatic ReAuth invalidation."""

from __future__ import annotations

from django.contrib.auth import get_user_model
from django.db.models.signals import post_save, pre_save

from .service import ReAuthService

_PASSWORD_CHANGED_ATTR = "_scoped_access_password_changed"


def _remember_password_change(sender, instance, raw=False, update_fields=None, **kwargs):
    if raw or instance.pk is None or (update_fields is not None and "password" not in update_fields):
        return
    previous = sender._default_manager.filter(pk=instance.pk).values_list("password", flat=True).first()
    setattr(instance, _PASSWORD_CHANGED_ATTR, previous is not None and previous != instance.password)


def _invalidate_after_password_change(sender, instance, raw=False, **kwargs):
    if raw:
        return
    if getattr(instance, _PASSWORD_CHANGED_ATTR, False):
        ReAuthService.invalidate_all_for_user(instance)
    if hasattr(instance, _PASSWORD_CHANGED_ATTR):
        delattr(instance, _PASSWORD_CHANGED_ATTR)


def connect_password_change_receivers() -> None:
    user_model = get_user_model()
    pre_save.connect(
        _remember_password_change,
        sender=user_model,
        weak=False,
        dispatch_uid="scoped_access.reauth.remember_password_change",
    )
    post_save.connect(
        _invalidate_after_password_change,
        sender=user_model,
        weak=False,
        dispatch_uid="scoped_access.reauth.invalidate_after_password_change",
    )
