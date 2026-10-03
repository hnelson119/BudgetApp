from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.http import HttpRequest
from webauthn import generate_registration_options, options_to_json, verify_registration_response
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from identity.models import PasskeyCredential, User

SESSION_PASSKEY_REGISTRATION = "security_passkey_registration"
_ALLOWED_TRANSPORTS = {"ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"}


@dataclass(frozen=True, slots=True)
class RegisteredPasskey:
    credential: PasskeyCredential
    total: int


def registration_options(request: HttpRequest, user: User) -> dict[str, Any]:
    if user.passkeys.count() >= settings.PASSKEY_MAX_CREDENTIALS:
        raise ValidationError("The passkey limit has been reached.")
    options = generate_registration_options(
        rp_id=settings.PASSKEY_RP_ID,
        rp_name=settings.PASSKEY_RP_NAME,
        user_id=user.pk.bytes,
        user_name=user.email,
        user_display_name=user.display_name or user.email,
        timeout=settings.PASSKEY_CHALLENGE_TIMEOUT_SECONDS * 1000,
        attestation=AttestationConveyancePreference.NONE,
        authenticator_selection=AuthenticatorSelectionCriteria(
            resident_key=ResidentKeyRequirement.REQUIRED,
            require_resident_key=True,
            user_verification=UserVerificationRequirement.REQUIRED,
        ),
        exclude_credentials=[
            PublicKeyCredentialDescriptor(id=base64url_to_bytes(value))
            for value in user.passkeys.values_list("credential_id", flat=True)
        ],
    )
    request.session[SESSION_PASSKEY_REGISTRATION] = {
        "challenge": bytes_to_base64url(options.challenge),
        "started_at": int(time.time()),
        "user_id": str(user.pk),
        "user_version": user.session_version,
    }
    payload = json.loads(options_to_json(options))
    if not isinstance(payload, dict):
        raise ValidationError("The passkey enrollment request could not be created.")
    return payload


def _consume_registration_challenge(request: HttpRequest, user: User) -> bytes:
    state = request.session.pop(SESSION_PASSKEY_REGISTRATION, None)
    if not isinstance(state, dict):
        raise ValidationError("The passkey enrollment request expired.")
    started_at = state.get("started_at")
    if (
        not isinstance(started_at, int)
        or int(time.time()) - started_at >= settings.PASSKEY_CHALLENGE_TIMEOUT_SECONDS
        or state.get("user_id") != str(user.pk)
        or state.get("user_version") != user.session_version
        or not isinstance(state.get("challenge"), str)
    ):
        raise ValidationError("The passkey enrollment request expired.")
    return base64url_to_bytes(state["challenge"])


def _transports(credential: dict[str, Any]) -> list[str]:
    response = credential.get("response")
    raw = response.get("transports", []) if isinstance(response, dict) else []
    if not isinstance(raw, list) or len(raw) > 8:
        raise ValidationError("The passkey transports were invalid.")
    values = sorted({str(value) for value in raw})
    if any(value not in _ALLOWED_TRANSPORTS for value in values):
        raise ValidationError("The passkey transports were invalid.")
    return values


@transaction.atomic
def register_passkey(
    request: HttpRequest,
    user: User,
    *,
    name: str,
    credential: dict[str, Any],
) -> RegisteredPasskey:
    normalized_name = name.strip()
    if not normalized_name or len(normalized_name) > 80:
        raise ValidationError("Provide a passkey name of 1 to 80 characters.")
    challenge = _consume_registration_challenge(request, user)
    locked_user = User.objects.select_for_update().get(pk=user.pk)
    if locked_user.session_version != user.session_version:
        raise ValidationError("The account security state changed; start again.")
    if locked_user.passkeys.count() >= settings.PASSKEY_MAX_CREDENTIALS:
        raise ValidationError("The passkey limit has been reached.")
    verification = verify_registration_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=settings.PASSKEY_RP_ID,
        expected_origin=settings.PASSKEY_ORIGIN,
        require_user_verification=True,
    )
    try:
        stored = PasskeyCredential.objects.create(
            user=locked_user,
            name=normalized_name,
            credential_id=bytes_to_base64url(verification.credential_id),
            public_key=verification.credential_public_key,
            sign_count=verification.sign_count,
            device_type=verification.credential_device_type.value,
            backed_up=verification.credential_backed_up,
            transports=_transports(credential),
        )
    except IntegrityError as error:
        raise ValidationError("That passkey or passkey name is already registered.") from error
    return RegisteredPasskey(credential=stored, total=locked_user.passkeys.count())


def parse_registration_body(body: bytes) -> tuple[str, dict[str, Any]]:
    if not body or len(body) > 32 * 1024:
        raise ValidationError("The passkey response was invalid.")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("The passkey response was invalid.") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("credential"), dict):
        raise ValidationError("The passkey response was invalid.")
    return str(payload.get("name", "")), payload["credential"]
