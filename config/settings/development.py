"""Local development settings."""

from .base import *  # noqa: F403

DEBUG = True
SESSION_COOKIE_NAME = "budget_dev_sessionid"
CSRF_COOKIE_NAME = "budget_dev_csrftoken"
