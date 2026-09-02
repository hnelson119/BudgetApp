from typing import Any

from django import forms
from django.contrib.auth.forms import AuthenticationForm, PasswordChangeForm
from django.core.exceptions import ValidationError

GENERIC_LOGIN_ERROR = "The email or password was not accepted."


class SecureAuthenticationForm(AuthenticationForm):
    def __init__(
        self,
        *args: Any,
        authentication_blocked: bool = False,
        **kwargs: Any,
    ) -> None:
        self.authentication_blocked = authentication_blocked
        super().__init__(*args, **kwargs)

    username = forms.EmailField(
        label="Email",
        max_length=254,
        widget=forms.EmailInput(
            attrs={
                "autocomplete": "username",
                "autofocus": True,
                "inputmode": "email",
            }
        ),
    )
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )

    def get_invalid_login_error(self) -> ValidationError:
        return ValidationError(GENERIC_LOGIN_ERROR, code="invalid_login")

    def clean(self) -> dict[str, Any]:
        if self.authentication_blocked:
            raise self.get_invalid_login_error()
        return super().clean()

    def confirm_login_allowed(self, user: Any) -> None:
        if not user.is_active:
            raise self.get_invalid_login_error()


class MfaVerificationForm(forms.Form):
    code = forms.CharField(
        label="Authenticator or recovery code",
        min_length=6,
        max_length=64,
        strip=True,
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "autofocus": True,
                "spellcheck": "false",
            }
        ),
    )

    def clean_code(self) -> str:
        return str(self.cleaned_data["code"]).strip()


class TotpEnrollmentForm(forms.Form):
    code = forms.RegexField(
        label="6-digit code",
        regex=r"^[0-9]{6}$",
        error_messages={"invalid": "Enter the 6-digit code from your authenticator app."},
        widget=forms.TextInput(
            attrs={
                "autocomplete": "one-time-code",
                "autofocus": True,
                "inputmode": "numeric",
                "pattern": "[0-9]{6}",
            }
        ),
    )


class RecoveryCodesConfirmationForm(forms.Form):
    saved = forms.BooleanField(
        label="I saved these recovery codes somewhere secure.",
        required=True,
    )


class ReauthenticationForm(forms.Form):
    password = forms.CharField(
        label="Password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password"}),
    )
    code = forms.CharField(
        label="Authenticator or recovery code",
        min_length=6,
        max_length=64,
        strip=True,
        widget=forms.TextInput(attrs={"autocomplete": "one-time-code", "spellcheck": "false"}),
    )


class SecurePasswordChangeForm(PasswordChangeForm):
    old_password = forms.CharField(
        label="Current password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "current-password", "autofocus": True}),
    )
    new_password1 = forms.CharField(
        label="New password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )
    new_password2 = forms.CharField(
        label="Confirm new password",
        strip=False,
        widget=forms.PasswordInput(attrs={"autocomplete": "new-password"}),
    )

    def clean_new_password1(self) -> str:
        password = str(self.cleaned_data["new_password1"])
        if self.user.check_password(password):
            raise ValidationError(
                "The new password must be different from the current password.",
                code="password_unchanged",
            )
        return password


class SessionRevocationForm(forms.Form):
    session_reference = forms.RegexField(regex=r"^[0-9a-f]{64}$", max_length=64)
