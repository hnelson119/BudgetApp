from typing import Any

from django import forms
from django.contrib.auth.forms import AuthenticationForm
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
