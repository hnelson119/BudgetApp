from __future__ import annotations

import json
import time
from binascii import Error as BinasciiError
from dataclasses import dataclass
from typing import Any

from django.conf import settings
from django.core.exceptions import ValidationError
from django.db import IntegrityError, transaction
from django.http import HttpRequest
from django.utils import timezone
from webauthn import (
    generate_authentication_options,
    generate_registration_options,
    options_to_json,
    verify_authentication_response,
    verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import (
    AttestationConveyancePreference,
    AuthenticatorSelectionCriteria,
    AuthenticatorTransport,
    PublicKeyCredentialDescriptor,
    ResidentKeyRequirement,
    UserVerificationRequirement,
)

from identity.models import PasskeyCredential, User

SESSION_PASSKEY_REGISTRATION = "security_passkey_registration"
SESSION_PASSKEY_AUTHENTICATION = "security_passkey_authentication"
_ALLOWED_TRANSPORTS = {"ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"}
_AUTHENTICATION_MODES = {"login", "reauthentication"}


@dataclass(frozen=True, slots=True)
class RegisteredPasskey:
    credential: PasskeyCredential
    total: int


@dataclass(frozen=True, slots=True)
class AuthenticatedPasskey:
    credential: PasskeyCredential
    user: User
    next_url: str


def authentication_options(
    request: HttpRequest,
    *,
    mode: str,
    next_url: str,
    user: User | None = None,
) -> dict[str, Any]:
    if mode not in _AUTHENTICATION_MODES or (mode == "reauthentication") != (user is not None):
        raise ValidationError("The passkey authentication request was invalid.")
    credentials = None
    if user is not None:
        stored = tuple(user.passkeys.all())
        if not stored:
            raise ValidationError("No passkey is available for this account.")
        try:
            credentials = [
                PublicKeyCredentialDescriptor(
                    id=base64url_to_bytes(item.credential_id),
                    transports=[AuthenticatorTransport(value) for value in item.transports],
                )
                for item in stored
            ]
        except (BinasciiError, TypeError, ValueError) as error:
            raise ValidationError("The stored passkey metadata was invalid.") from error
    elif request.user.is_authenticated:
        raise ValidationError("The passkey authentication request was invalid.")

    options = generate_authentication_options(
        rp_id=settings.PASSKEY_RP_ID,
        timeout=settings.PASSKEY_CHALLENGE_TIMEOUT_SECONDS * 1000,
        allow_credentials=credentials,
        user_verification=UserVerificationRequirement.REQUIRED,
    )
    request.session[SESSION_PASSKEY_AUTHENTICATION] = {
        "challenge": bytes_to_base64url(options.challenge),
        "mode": mode,
        "next_url": next_url,
        "started_at": int(time.time()),
        "user_id": str(user.pk) if user is not None else None,
        "user_version": user.session_version if user is not None else None,
    }
    payload = json.loads(options_to_json(options))
    if not isinstance(payload, dict):
        raise ValidationError("The passkey authentication request could not be created.")
    return payload


def _consume_authentication_challenge(
    request: HttpRequest,
    *,
    mode: str,
    user: User | None,
) -> tuple[bytes, str]:
    state = request.session.pop(SESSION_PASSKEY_AUTHENTICATION, None)
    if not isinstance(state, dict):
        raise ValidationError("The passkey authentication request expired.")
    started_at = state.get("started_at")
    expected_user_id = str(user.pk) if user is not None else None
    expected_user_version = user.session_version if user is not None else None
    if (
        mode not in _AUTHENTICATION_MODES
        or not isinstance(started_at, int)
        or int(time.time()) - started_at >= settings.PASSKEY_CHALLENGE_TIMEOUT_SECONDS
        or state.get("mode") != mode
        or state.get("user_id") != expected_user_id
        or state.get("user_version") != expected_user_version
        or not isinstance(state.get("challenge"), str)
        or not isinstance(state.get("next_url"), str)
    ):
        raise ValidationError("The passkey authentication request expired.")
    return base64url_to_bytes(state["challenge"]), state["next_url"]


def _canonical_credential_id(credential: dict[str, Any]) -> str:
    credential_id = credential.get("id")
    raw_id = credential.get("rawId")
    if not isinstance(credential_id, str) or not isinstance(raw_id, str):
        raise ValidationError("The passkey response was invalid.")
    try:
        decoded = base64url_to_bytes(raw_id)
    except (BinasciiError, ValueError) as error:
        raise ValidationError("The passkey response was invalid.") from error
    canonical = bytes_to_base64url(decoded)
    if canonical != raw_id or credential_id != raw_id:
        raise ValidationError("The passkey response was invalid.")
    return canonical


def _validate_user_handle(credential: dict[str, Any], user: User, *, required: bool) -> None:
    response = credential.get("response")
    if not isinstance(response, dict):
        raise ValidationError("The passkey response was invalid.")
    user_handle = response.get("userHandle")
    if user_handle is None and not required:
        return
    if not isinstance(user_handle, str):
        raise ValidationError("The passkey response was invalid.")
    try:
        decoded = base64url_to_bytes(user_handle)
    except (BinasciiError, ValueError) as error:
        raise ValidationError("The passkey response was invalid.") from error
    if bytes_to_base64url(decoded) != user_handle or decoded != user.pk.bytes:
        raise ValidationError("The passkey response was invalid.")


@transaction.atomic
def authenticate_passkey(
    request: HttpRequest,
    *,
    mode: str,
    credential: dict[str, Any],
    user: User | None = None,
) -> AuthenticatedPasskey:
    challenge, next_url = _consume_authentication_challenge(request, mode=mode, user=user)
    credential_id = _canonical_credential_id(credential)
    stored = (
        PasskeyCredential.objects.select_for_update()
        .select_related("user")
        .filter(credential_id=credential_id)
        .first()
    )
    if stored is None or (user is not None and stored.user_id != user.pk):
        raise ValidationError("The passkey response was invalid.")
    authenticated_user = stored.user
    if (
        not authenticated_user.is_active
        or not authenticated_user.household_memberships.filter(is_active=True).exists()
        or authenticated_user.mfa_enrolled_at is None
    ):
        raise ValidationError("The passkey response was invalid.")
    _validate_user_handle(credential, authenticated_user, required=mode == "login")
    verification = verify_authentication_response(
        credential=credential,
        expected_challenge=challenge,
        expected_rp_id=settings.PASSKEY_RP_ID,
        expected_origin=settings.PASSKEY_ORIGIN,
        credential_public_key=bytes(stored.public_key),
        credential_current_sign_count=stored.sign_count,
        require_user_verification=True,
    )
    stored.sign_count = verification.new_sign_count
    stored.device_type = verification.credential_device_type.value
    stored.backed_up = verification.credential_backed_up
    stored.last_used_at = timezone.now()
    stored.save(update_fields=("sign_count", "device_type", "backed_up", "last_used_at"))
    return AuthenticatedPasskey(
        credential=stored,
        user=authenticated_user,
        next_url=next_url,
    )


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


def parse_authentication_body(body: bytes) -> dict[str, Any]:
    if not body or len(body) > 32 * 1024:
        raise ValidationError("The passkey response was invalid.")
    try:
        payload = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValidationError("The passkey response was invalid.") from error
    if not isinstance(payload, dict) or not isinstance(payload.get("credential"), dict):
        raise ValidationError("The passkey response was invalid.")
    return payload["credential"]
