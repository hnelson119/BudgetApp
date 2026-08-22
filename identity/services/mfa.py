from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import secrets
import struct
import time
from dataclasses import dataclass
from urllib.parse import quote, urlencode

import qrcode
import qrcode.image.svg
from cryptography.fernet import Fernet, InvalidToken
from django.conf import settings
from django.contrib.auth.hashers import check_password, make_password
from django.core.exceptions import ImproperlyConfigured
from django.db import transaction
from django.utils import timezone

from identity.models import MfaCredential, RecoveryCode, User

_RECOVERY_NORMALIZER = re.compile(r"[^A-Za-z0-9]")


@dataclass(frozen=True)
class EnrollmentResult:
    credential: MfaCredential
    secret: str


@dataclass(frozen=True)
class ConfirmedEnrollment:
    recovery_codes: tuple[str, ...]
    session_version: int


def _fernet() -> Fernet:
    raw_key = str(settings.MFA_ENCRYPTION_KEY).encode()
    derived_key = hashlib.sha256(b"household-budget:mfa:v1:" + raw_key).digest()
    return Fernet(base64.urlsafe_b64encode(derived_key))


def _encrypt_secret(*, user: User, secret: str) -> str:
    payload = json.dumps(
        {
            "version": settings.MFA_ENCRYPTION_KEY_VERSION,
            "user_id": str(user.pk),
            "secret": secret,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return _fernet().encrypt(payload).decode()


def decrypt_secret(credential: MfaCredential) -> str:
    try:
        payload = json.loads(_fernet().decrypt(credential.encrypted_secret.encode()))
    except (InvalidToken, UnicodeError, json.JSONDecodeError, TypeError) as error:
        raise ImproperlyConfigured("The stored MFA credential cannot be decrypted.") from error

    if (
        payload.get("version") != credential.key_version
        or payload.get("user_id") != str(credential.user_id)
        or not isinstance(payload.get("secret"), str)
    ):
        raise ImproperlyConfigured("The stored MFA credential is invalid.")
    return str(payload["secret"])


def generate_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def provisioning_uri(*, user: User, secret: str) -> str:
    issuer = str(settings.MFA_ISSUER)
    label = quote(f"{issuer}:{user.email}", safe="")
    query = urlencode(
        {
            "secret": secret,
            "issuer": issuer,
            "algorithm": "SHA1",
            "digits": "6",
            "period": str(settings.MFA_TOTP_PERIOD_SECONDS),
        }
    )
    return f"otpauth://totp/{label}?{query}"


def provisioning_qr_data_uri(*, user: User, secret: str) -> str:
    image = qrcode.make(
        provisioning_uri(user=user, secret=secret),
        image_factory=qrcode.image.svg.SvgPathFillImage,
        box_size=8,
        border=4,
    )
    svg = image.to_string(encoding="utf-8")
    return "data:image/svg+xml;base64," + base64.b64encode(svg).decode()


def _decode_totp_secret(secret: str) -> bytes:
    padding = "=" * ((8 - len(secret) % 8) % 8)
    return base64.b32decode(secret + padding, casefold=True)


def totp_code(secret: str, *, timestamp: int | None = None) -> str:
    current_time = int(time.time()) if timestamp is None else timestamp
    step = current_time // settings.MFA_TOTP_PERIOD_SECONDS
    digest = hmac.new(
        _decode_totp_secret(secret),
        struct.pack(">Q", step),
        hashlib.sha1,
    ).digest()
    offset = digest[-1] & 0x0F
    binary = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{binary % 1_000_000:06d}"


def _matching_totp_step(secret: str, code: str, *, timestamp: int | None = None) -> int | None:
    normalized = code.strip()
    if len(normalized) != 6 or not normalized.isascii() or not normalized.isdigit():
        return None

    current_time = int(time.time()) if timestamp is None else timestamp
    current_step = current_time // settings.MFA_TOTP_PERIOD_SECONDS
    matched_step: int | None = None
    for offset in range(
        -settings.MFA_TOTP_CLOCK_DRIFT_STEPS,
        settings.MFA_TOTP_CLOCK_DRIFT_STEPS + 1,
    ):
        candidate_step = current_step + offset
        candidate_time = candidate_step * settings.MFA_TOTP_PERIOD_SECONDS
        if hmac.compare_digest(totp_code(secret, timestamp=candidate_time), normalized):
            matched_step = candidate_step
    return matched_step


@transaction.atomic
def begin_enrollment(user: User) -> EnrollmentResult:
    credential = MfaCredential.objects.select_for_update().filter(user=user).first()
    if credential is None:
        secret = generate_totp_secret()
        credential = MfaCredential.objects.create(
            user=user,
            encrypted_secret=_encrypt_secret(user=user, secret=secret),
            key_version=settings.MFA_ENCRYPTION_KEY_VERSION,
        )
        return EnrollmentResult(credential=credential, secret=secret)
    return EnrollmentResult(credential=credential, secret=decrypt_secret(credential))


def _generate_recovery_code() -> tuple[str, str, str]:
    identifier = secrets.token_hex(4).upper()
    secret = base64.b32encode(secrets.token_bytes(15)).decode().rstrip("=")
    display = "-".join((identifier, *(secret[index : index + 4] for index in range(0, 24, 4))))
    return identifier, secret, display


def _replace_recovery_codes(user: User) -> tuple[str, ...]:
    RecoveryCode.objects.filter(user=user).delete()
    display_codes: list[str] = []
    for _ in range(settings.MFA_RECOVERY_CODE_COUNT):
        identifier, secret, display = _generate_recovery_code()
        RecoveryCode.objects.create(
            user=user,
            identifier=identifier,
            code_hash=make_password(secret),
        )
        display_codes.append(display)
    return tuple(display_codes)


@transaction.atomic
def confirm_enrollment(user: User, code: str) -> ConfirmedEnrollment | None:
    locked_user = User.objects.select_for_update().get(pk=user.pk)
    credential = MfaCredential.objects.select_for_update().filter(user=locked_user).first()
    if credential is None or credential.confirmed_at is not None:
        return None

    step = _matching_totp_step(decrypt_secret(credential), code)
    if step is None or (
        credential.last_used_step is not None and step <= credential.last_used_step
    ):
        return None

    now = timezone.now()
    credential.confirmed_at = now
    credential.last_used_step = step
    credential.recovery_codes_confirmed_at = None
    credential.save(
        update_fields=(
            "confirmed_at",
            "last_used_step",
            "recovery_codes_confirmed_at",
            "updated_at",
        )
    )
    locked_user.mfa_enrolled_at = now
    locked_user.session_version += 1
    locked_user.save(update_fields=("mfa_enrolled_at", "session_version"))
    codes = _replace_recovery_codes(locked_user)
    return ConfirmedEnrollment(codes, locked_user.session_version)


@transaction.atomic
def confirm_recovery_codes_saved(user: User) -> bool:
    credential = MfaCredential.objects.select_for_update().filter(user=user).first()
    if credential is None or credential.confirmed_at is None:
        return False
    if not RecoveryCode.objects.filter(user=user, used_at__isnull=True).exists():
        return False
    credential.recovery_codes_confirmed_at = timezone.now()
    credential.save(update_fields=("recovery_codes_confirmed_at", "updated_at"))
    return True


def mfa_is_ready(user: User) -> bool:
    return bool(
        user.mfa_enrolled_at
        and MfaCredential.objects.filter(
            user=user,
            confirmed_at__isnull=False,
            recovery_codes_confirmed_at__isnull=False,
        ).exists()
    )


def mfa_verification_required(user: User) -> bool:
    return bool(
        user.mfa_enrolled_at
        or MfaCredential.objects.filter(user=user, confirmed_at__isnull=False).exists()
    )


@transaction.atomic
def verify_and_consume_totp(user: User, code: str) -> bool:
    credential = (
        MfaCredential.objects.select_for_update()
        .filter(
            user=user,
            confirmed_at__isnull=False,
        )
        .first()
    )
    if credential is None:
        return False
    step = _matching_totp_step(decrypt_secret(credential), code)
    if step is None or (
        credential.last_used_step is not None and step <= credential.last_used_step
    ):
        return False
    credential.last_used_step = step
    credential.save(update_fields=("last_used_step", "updated_at"))
    return True


def _normalize_recovery_code(code: str) -> tuple[str, str] | None:
    normalized = _RECOVERY_NORMALIZER.sub("", code).upper()
    if len(normalized) != 32 or not normalized.isascii() or not normalized.isalnum():
        return None
    return normalized[:8], normalized[8:]


@transaction.atomic
def verify_and_consume_recovery_code(user: User, code: str) -> bool:
    if not MfaCredential.objects.filter(user=user, confirmed_at__isnull=False).exists():
        return False
    normalized = _normalize_recovery_code(code)
    if normalized is None:
        return False
    identifier, secret = normalized
    recovery_code = (
        RecoveryCode.objects.select_for_update()
        .filter(
            user=user,
            identifier=identifier,
            used_at__isnull=True,
        )
        .first()
    )
    if recovery_code is None or not check_password(secret, recovery_code.code_hash):
        return False
    recovery_code.used_at = timezone.now()
    recovery_code.save(update_fields=("used_at",))
    return True


@transaction.atomic
def reset_mfa(user: User) -> int:
    MfaCredential.objects.filter(user=user).delete()
    RecoveryCode.objects.filter(user=user).delete()
    locked_user = User.objects.select_for_update().get(pk=user.pk)
    locked_user.mfa_enrolled_at = None
    locked_user.session_version += 1
    locked_user.save(update_fields=("mfa_enrolled_at", "session_version"))
    return locked_user.session_version
