from __future__ import annotations

import logging

from django.db.models.signals import post_delete, post_save, pre_save
from django.dispatch import receiver

from identity.models import User
from identity.services.sessions import delete_sessions_for_user_identity

_TERMINATE_SESSIONS_AFTER_SAVE = "_budget_terminate_sessions_after_save"
security_logger = logging.getLogger("security")


@receiver(pre_save, sender=User)
def mark_account_deactivation(
    sender: type[User],
    instance: User,
    *,
    raw: bool,
    using: str,
    update_fields: frozenset[str] | None,
    **_: object,
) -> None:
    setattr(instance, _TERMINATE_SESSIONS_AFTER_SAVE, False)
    if (
        raw
        or instance._state.adding
        or instance.is_active
        or (update_fields is not None and "is_active" not in update_fields)
    ):
        return
    was_active = sender.objects.using(using).filter(pk=instance.pk, is_active=True).exists()
    setattr(instance, _TERMINATE_SESSIONS_AFTER_SAVE, was_active)


@receiver(post_save, sender=User)
def terminate_sessions_after_account_deactivation(
    sender: type[User],
    instance: User,
    **_: object,
) -> None:
    del sender
    if not getattr(instance, _TERMINATE_SESSIONS_AFTER_SAVE, False):
        return
    try:
        deleted = delete_sessions_for_user_identity(str(instance.pk))
    finally:
        delattr(instance, _TERMINATE_SESSIONS_AFTER_SAVE)
    security_logger.warning(
        "User account disabled; application sessions terminated.",
        extra={
            "event": "auth.session_revoked",
            "scope": "account_disabled",
            "stored_records_removed": deleted,
        },
    )


@receiver(post_delete, sender=User)
def terminate_sessions_after_account_deletion(
    sender: type[User],
    instance: User,
    **_: object,
) -> None:
    del sender
    deleted = delete_sessions_for_user_identity(str(instance.pk))
    security_logger.warning(
        "User account deleted; application sessions terminated.",
        extra={
            "event": "auth.session_revoked",
            "scope": "account_deleted",
            "stored_records_removed": deleted,
        },
    )
