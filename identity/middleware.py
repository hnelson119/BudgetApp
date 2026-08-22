from collections.abc import Callable

from django.http import HttpRequest, HttpResponse

from identity.services.sessions import validate_active_session


class SecureSessionMiddleware:
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        if request.user.is_authenticated:
            validate_active_session(request, request.user)
        return self.get_response(request)
