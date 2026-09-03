from __future__ import annotations

import secrets
from dataclasses import dataclass
from functools import cache

from django.contrib.auth.hashers import check_password, make_password
from django.contrib.auth.password_validation import password_changed
from django.db import transaction

from audit.services import append_event
from households.models import HouseholdMembership
from identity.models import User
from identity.services.mfa import verify_and_consume_password_recovery_factor


@dataclass(frozen=True, slots=True)
class PasswordRecoveryResult:
    accepted: bool


@cache
def _dummy_password_hash() -> str:
    return make_password(secrets.token_urlsafe(32))


@transaction.atomic
def recover_forgotten_password(
    *,
    email: str,
    code: str,
    new_password: str,
    request_id: str,
) -> PasswordRecoveryResult:
    normalized_email = email.strip().lower()
    candidate = User.objects.filter(email=normalized_email).only("pk").first()
    user = (
        User.objects.select_for_update().filter(pk=candidate.pk, is_active=True).first()
        if candidate is not None
        else None
    )
    memberships = (
        tuple(
            HouseholdMembership.objects.select_for_update()
            .filter(user=user, is_active=True)
            .select_related("household")
            .order_by("household_id")
        )
        if user is not None
        else ()
    )
    selected_hash = user.password if user is not None and memberships else _dummy_password_hash()
    password_is_reused = check_password(new_password, selected_hash)
    verification_user = (
        user if user is not None and memberships and not password_is_reused else None
    )
    method = verify_and_consume_password_recovery_factor(verification_user, code)

    if user is None:
        return PasswordRecoveryResult(accepted=False)
    if not memberships or password_is_reused or method is None:
        for membership in memberships:
            append_event(
                household=membership.household,
                actor=None,
                action="auth.password_recovery_failed",
                entity_type="identity.user",
                entity_id=user.pk,
                request_id=request_id,
                after={"factor": "totp_or_recovery_code"},
            )
        return PasswordRecoveryResult(accepted=False)

    previous_version = user.session_version
    user.set_password(new_password)
    user.session_version += 1
    user.save(update_fields=("password", "session_version"))
    password_changed(new_password, user)
    for membership in memberships:
        append_event(
            household=membership.household,
            actor=None,
            action="auth.password_recovered",
            entity_type="identity.user",
            entity_id=user.pk,
            request_id=request_id,
            before={"session_version": previous_version},
            after={
                "credential_changed": True,
                "factor": method,
                "sessions_revoked": True,
                "session_version": user.session_version,
            },
        )
    return PasswordRecoveryResult(accepted=True)
