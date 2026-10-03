import json
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from django.conf import settings
from django.test import Client
from django.urls import reverse
from webauthn.helpers import bytes_to_base64url
from webauthn.helpers.structs import CredentialDeviceType

from audit.models import AuditEvent
from households.models import Household, HouseholdMembership
from identity.models import PasskeyCredential, User
from identity.services.mfa import (
    begin_enrollment,
    confirm_enrollment,
    confirm_recovery_codes_saved,
    totp_code,
)
from identity.services.sessions import SESSION_AUTH_VERIFIED_AT, SESSION_USER_VERSION

PASSWORD = "passkey-test-current-passphrase"  # pragma: allowlist secret


@pytest.fixture
def passkey_user(db):  # type: ignore[no-untyped-def]
    household = Household.objects.create(name="Passkey Household")
    user = User.objects.create_user(
        email="passkey@example.com",
        password=PASSWORD,
        display_name="Passkey Owner",
    )
    HouseholdMembership.objects.create(household=household, user=user)
    enrollment = begin_enrollment(user)
    confirmed = confirm_enrollment(user, totp_code(enrollment.secret))
    assert confirmed is not None
    assert confirm_recovery_codes_saved(user) is True
    user.refresh_from_db()
    client = Client()
    response = client.post(
        reverse("identity:login"),
        {"username": user.email, "password": PASSWORD},
    )
    assert response.url.startswith(reverse("identity:mfa-verify"))
    response = client.post(
        reverse("identity:mfa-verify"),
        {"code": confirmed.recovery_codes[0]},
    )
    assert response.url == reverse("core:home")
    return household, user, client


def _credential_payload() -> dict[str, object]:
    return {
        "id": "credential-id",
        "rawId": "credential-id",
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "attestationObject": "attestation",
            "clientDataJSON": "client-data",
            "transports": ["internal", "hybrid"],
        },
    }


def _authentication_payload(user: User, credential_id: str) -> dict[str, object]:
    return {
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "authenticatorAttachment": "platform",
        "clientExtensionResults": {},
        "response": {
            "authenticatorData": "authenticator-data",
            "clientDataJSON": "client-data",
            "signature": "signature",
            "userHandle": bytes_to_base64url(user.pk.bytes),
        },
    }


def _authentication_verification(*, sign_count: int = 8) -> SimpleNamespace:
    return SimpleNamespace(
        new_sign_count=sign_count,
        credential_device_type=CredentialDeviceType.MULTI_DEVICE,
        credential_backed_up=True,
    )


@pytest.mark.django_db
def test_recent_mfa_session_registers_user_verified_resident_passkey(passkey_user) -> None:  # type: ignore[no-untyped-def]
    household, user, client = passkey_user
    options = client.post(reverse("identity:passkey-registration-options"))

    assert options.status_code == 200
    document = options.json()
    assert document["rp"]["id"] == settings.PASSKEY_RP_ID
    assert document["user"]["name"] == user.email
    assert document["authenticatorSelection"]["residentKey"] == "required"
    assert document["authenticatorSelection"]["userVerification"] == "required"
    assert document["attestation"] == "none"

    verification = SimpleNamespace(
        credential_id=b"registered-credential",
        credential_public_key=b"public-key-material",
        sign_count=7,
        credential_device_type=CredentialDeviceType.MULTI_DEVICE,
        credential_backed_up=True,
    )
    with patch(
        "identity.services.passkeys.verify_registration_response",
        return_value=verification,
    ) as verify:
        response = client.post(
            reverse("identity:passkey-registration-complete"),
            data=json.dumps({"name": "Personal phone", "credential": _credential_payload()}),
            content_type="application/json",
        )

    assert response.status_code == 200
    verify.assert_called_once()
    assert verify.call_args.kwargs["expected_rp_id"] == settings.PASSKEY_RP_ID
    assert verify.call_args.kwargs["expected_origin"] == settings.PASSKEY_ORIGIN
    assert verify.call_args.kwargs["require_user_verification"] is True
    credential = PasskeyCredential.objects.get(user=user)
    assert credential.name == "Personal phone"
    assert bytes(credential.public_key) == b"public-key-material"
    assert credential.sign_count == 7
    assert credential.device_type == "multi_device"
    assert credential.backed_up is True
    assert credential.transports == ["hybrid", "internal"]
    event = AuditEvent.objects.get(household=household, action="auth.passkey_registered")
    assert event.after_payload == {"passkey_count": 1}
    assert "credential" not in json.dumps(event.after_payload)


@pytest.mark.django_db
def test_passkey_changes_require_recent_authentication(passkey_user) -> None:  # type: ignore[no-untyped-def]
    _, user, client = passkey_user
    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = int(time.time()) - settings.RECENT_AUTH_TIMEOUT_SECONDS - 1
    session.save()
    credential = PasskeyCredential.objects.create(
        user=user,
        name="Existing key",
        credential_id="existing-key",
        public_key=b"public-key",
        device_type="single_device",
    )

    assert client.post(reverse("identity:passkey-registration-options")).status_code == 403
    assert (
        client.post(
            reverse("identity:passkey-registration-complete"),
            data=b"{}",
            content_type="application/json",
        ).status_code
        == 403
    )
    deletion = client.post(reverse("identity:passkey-delete", args=(credential.pk,)))
    assert deletion.status_code == 302
    assert deletion.url.startswith(reverse("identity:reauthenticate"))
    assert PasskeyCredential.objects.filter(pk=credential.pk).exists()


@pytest.mark.django_db
def test_passkey_removal_is_owner_scoped_and_audited(passkey_user) -> None:  # type: ignore[no-untyped-def]
    household, user, client = passkey_user
    own = PasskeyCredential.objects.create(
        user=user,
        name="Own key",
        credential_id="own-key",
        public_key=b"public-key",
        device_type="single_device",
    )
    outsider = User.objects.create_user(email="outsider@example.com", password=PASSWORD)
    foreign = PasskeyCredential.objects.create(
        user=outsider,
        name="Foreign key",
        credential_id="foreign-key",
        public_key=b"public-key",
        device_type="single_device",
    )

    assert client.get(reverse("identity:passkey-delete", args=(own.pk,))).status_code == 405
    assert client.post(reverse("identity:passkey-delete", args=(foreign.pk,))).status_code == 404
    response = client.post(reverse("identity:passkey-delete", args=(own.pk,)))

    assert response.status_code == 302
    assert not PasskeyCredential.objects.filter(pk=own.pk).exists()
    assert PasskeyCredential.objects.filter(pk=foreign.pk).exists()
    event = AuditEvent.objects.get(household=household, action="auth.passkey_removed")
    assert event.after_payload == {"passkey_count": 0}


@pytest.mark.django_db
def test_passkey_endpoints_require_login_and_csrf(passkey_user) -> None:  # type: ignore[no-untyped-def]
    _, user, _ = passkey_user
    anonymous = Client()
    assert anonymous.post(reverse("identity:passkey-registration-options")).status_code == 302
    csrf_client = Client(enforce_csrf_checks=True)
    csrf_client.force_login(user)
    assert csrf_client.post(reverse("identity:passkey-registration-options")).status_code == 403


@pytest.mark.django_db
def test_discoverable_passkey_login_requires_user_verification_and_establishes_session(
    passkey_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user, _ = passkey_user
    credential_id = bytes_to_base64url(b"login-authenticator")
    passkey = PasskeyCredential.objects.create(
        user=user,
        name="Login key",
        credential_id=credential_id,
        public_key=b"public-key",
        sign_count=7,
        device_type="single_device",
    )
    client = Client()

    options = client.post(
        reverse("identity:passkey-login-options"),
        {"next": reverse("identity:account-security")},
    )

    assert options.status_code == 200
    assert options.json()["userVerification"] == "required"
    assert not options.json().get("allowCredentials")
    with patch(
        "identity.services.passkeys.verify_authentication_response",
        return_value=_authentication_verification(),
    ) as verify:
        response = client.post(
            reverse("identity:passkey-login-complete"),
            data=json.dumps({"credential": _authentication_payload(user, credential_id)}),
            content_type="application/json",
        )

    assert response.status_code == 200
    assert response.json()["redirect"] == reverse("identity:account-security")
    assert client.session[SESSION_USER_VERSION] == user.session_version
    verify.assert_called_once()
    assert verify.call_args.kwargs["require_user_verification"] is True
    assert verify.call_args.kwargs["credential_current_sign_count"] == 7
    passkey.refresh_from_db()
    assert passkey.sign_count == 8
    assert passkey.backed_up is True
    assert passkey.last_used_at is not None
    event = AuditEvent.objects.filter(
        household=household,
        action="auth.login_succeeded",
    ).latest("sequence")
    assert event.after_payload == {"authentication_method": "passkey"}


@pytest.mark.django_db
def test_passkey_reauthentication_is_owner_bound_single_use_and_audited(
    passkey_user,
) -> None:  # type: ignore[no-untyped-def]
    household, user, client = passkey_user
    credential_id = bytes_to_base64url(b"reauth-authenticator")
    passkey = PasskeyCredential.objects.create(
        user=user,
        name="Reauthentication key",
        credential_id=credential_id,
        public_key=b"public-key",
        sign_count=3,
        device_type="single_device",
        transports=["internal"],
    )
    session = client.session
    session[SESSION_AUTH_VERIFIED_AT] = 1
    session.save()

    options = client.post(
        reverse("identity:passkey-reauthentication-options"),
        {"next": reverse("identity:account-security")},
    )

    assert options.status_code == 200
    assert options.json()["allowCredentials"][0]["id"] == credential_id
    with patch(
        "identity.services.passkeys.verify_authentication_response",
        return_value=_authentication_verification(sign_count=4),
    ):
        response = client.post(
            reverse("identity:passkey-reauthentication-complete"),
            data=json.dumps({"credential": _authentication_payload(user, credential_id)}),
            content_type="application/json",
        )
        replay = client.post(
            reverse("identity:passkey-reauthentication-complete"),
            data=json.dumps({"credential": _authentication_payload(user, credential_id)}),
            content_type="application/json",
        )

    assert response.status_code == 200
    assert response.json()["redirect"] == reverse("identity:account-security")
    assert client.session[SESSION_AUTH_VERIFIED_AT] > 1
    assert replay.status_code == 400
    passkey.refresh_from_db()
    assert passkey.sign_count == 4
    event = AuditEvent.objects.filter(
        household=household,
        action="auth.reauthentication_succeeded",
    ).latest("occurred_at")
    assert event.after_payload == {"method": "passkey"}


@pytest.mark.django_db
def test_passkey_login_rejects_wrong_user_handle_and_inactive_membership(passkey_user) -> None:  # type: ignore[no-untyped-def]
    household, user, _ = passkey_user
    credential_id = bytes_to_base64url(b"rejected-authenticator")
    passkey = PasskeyCredential.objects.create(
        user=user,
        name="Rejected key",
        credential_id=credential_id,
        public_key=b"public-key",
        sign_count=2,
        device_type="single_device",
    )
    client = Client()
    client.post(reverse("identity:passkey-login-options"))
    payload = _authentication_payload(user, credential_id)
    payload["response"]["userHandle"] = bytes_to_base64url(b"wrong-user")  # type: ignore[index]

    with patch("identity.services.passkeys.verify_authentication_response") as verify:
        response = client.post(
            reverse("identity:passkey-login-complete"),
            data=json.dumps({"credential": payload}),
            content_type="application/json",
        )

    assert response.status_code == 400
    assert response.json() == {"error": "Passkey sign-in was not accepted."}
    verify.assert_not_called()
    passkey.refresh_from_db()
    assert passkey.sign_count == 2

    HouseholdMembership.objects.filter(household=household, user=user).update(is_active=False)
    client.post(reverse("identity:passkey-login-options"))
    with patch("identity.services.passkeys.verify_authentication_response") as verify:
        response = client.post(
            reverse("identity:passkey-login-complete"),
            data=json.dumps({"credential": _authentication_payload(user, credential_id)}),
            content_type="application/json",
        )
    assert response.status_code == 400
    verify.assert_not_called()


@pytest.mark.django_db
def test_passkey_authentication_endpoints_enforce_csrf_and_authentication(passkey_user) -> None:  # type: ignore[no-untyped-def]
    _, user, _ = passkey_user
    anonymous = Client()
    assert anonymous.post(reverse("identity:passkey-reauthentication-options")).status_code == 302
    csrf_client = Client(enforce_csrf_checks=True)
    assert csrf_client.post(reverse("identity:passkey-login-options")).status_code == 403
    assert csrf_client.post(reverse("identity:passkey-login-complete")).status_code == 403
    csrf_client.force_login(user)
    assert csrf_client.post(reverse("identity:passkey-reauthentication-options")).status_code == 403
    assert (
        csrf_client.post(reverse("identity:passkey-reauthentication-complete")).status_code == 403
    )
