"""Local password policy controls that never disclose password-derived values."""

from __future__ import annotations

import hashlib
import json
import os
import re
import stat
import unicodedata
from dataclasses import dataclass
from datetime import date, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured, ValidationError
from django.utils.translation import gettext as _

CORPUS_MAGIC = b"HOUSEHOLD-BUDGET-BREACHED-PASSWORDS-V1\n"
CORPUS_METADATA_KEYS = frozenset(
    {
        "corpus_version",
        "entries",
        "generated_at",
        "payload_sha256",
        "selection",
        "source_name",
        "source_retrieved_at",
        "source_sha256",
        "source_url",
    }
)
HASH_BYTES = 40
HASH_RECORD_BYTES = HASH_BYTES + 1
MAX_METADATA_BYTES = 4096
MAX_METADATA_LABEL_CHARS = 512
MAX_SOURCE_URL_CHARS = 2048
_HEX_40 = re.compile(r"^[0-9A-F]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_LEET_TRANSLATION = str.maketrans(
    {
        "@": "a",
        "$": "s",
        "0": "o",
        "1": "i",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
    }
)


@dataclass(frozen=True)
class BreachedPasswordCorpus:
    """Validated metadata and fixed-width SHA-1 records."""

    metadata: dict[str, Any]
    payload: bytes

    def contains(self, digest: bytes) -> bool:
        """Binary-search a full uppercase SHA-1 digest without allocating a hash set."""

        low = 0
        high = int(self.metadata["entries"])
        while low < high:
            middle = (low + high) // 2
            offset = middle * HASH_RECORD_BYTES
            candidate = self.payload[offset : offset + HASH_BYTES]
            if candidate < digest:
                low = middle + 1
            else:
                high = middle
        if low >= int(self.metadata["entries"]):
            return False
        offset = low * HASH_RECORD_BYTES
        return self.payload[offset : offset + HASH_BYTES] == digest


def _parse_iso_date(value: Any, *, field: str) -> date:
    if not isinstance(value, str):
        raise ImproperlyConfigured(f"Breached-password corpus {field} must be an ISO date.")
    try:
        return date.fromisoformat(value)
    except ValueError as error:
        raise ImproperlyConfigured(
            f"Breached-password corpus {field} must be an ISO date."
        ) from error


def _is_valid_https_url(value: Any) -> bool:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > MAX_SOURCE_URL_CHARS
        or any(character.isspace() for character in value)
    ):
        return False
    try:
        parsed = urlsplit(value)
        _ = parsed.port
        return (
            parsed.scheme == "https"
            and parsed.hostname is not None
            and parsed.username is None
            and parsed.password is None
        )
    except ValueError:
        return False


def _is_valid_metadata_label(value: Any) -> bool:
    return (
        isinstance(value, str)
        and value == value.strip()
        and 0 < len(value) <= MAX_METADATA_LABEL_CHARS
        and value.isprintable()
    )


def _json_object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _validate_metadata(
    metadata: Any,
    *,
    minimum_entries: int,
    maximum_age_days: int,
) -> dict[str, Any]:
    if not isinstance(metadata, dict) or set(metadata) != CORPUS_METADATA_KEYS:
        raise ImproperlyConfigured("Breached-password corpus metadata is incomplete or unexpected.")
    if (
        not isinstance(metadata["corpus_version"], int)
        or isinstance(metadata["corpus_version"], bool)
        or metadata["corpus_version"] != 1
    ):
        raise ImproperlyConfigured("Breached-password corpus version is unsupported.")
    entries = metadata["entries"]
    if not isinstance(entries, int) or isinstance(entries, bool) or entries < minimum_entries:
        raise ImproperlyConfigured(
            f"Breached-password corpus must contain at least {minimum_entries} entries."
        )
    if not _is_valid_metadata_label(metadata["source_name"]):
        raise ImproperlyConfigured("Breached-password corpus source name is invalid.")
    source_url = metadata["source_url"]
    if not _is_valid_https_url(source_url):
        raise ImproperlyConfigured("Breached-password corpus source URL must use HTTPS.")
    if not _is_valid_metadata_label(metadata["selection"]):
        raise ImproperlyConfigured("Breached-password corpus selection description is invalid.")
    if (
        not isinstance(metadata["source_sha256"], str)
        or _HEX_64.fullmatch(metadata["source_sha256"]) is None
    ):
        raise ImproperlyConfigured("Breached-password corpus source digest is invalid.")
    if (
        not isinstance(metadata["payload_sha256"], str)
        or _HEX_64.fullmatch(metadata["payload_sha256"]) is None
    ):
        raise ImproperlyConfigured("Breached-password corpus payload digest is invalid.")

    retrieved_at = _parse_iso_date(metadata["source_retrieved_at"], field="source_retrieved_at")
    generated_at = _parse_iso_date(metadata["generated_at"], field="generated_at")
    today = date.today()
    if retrieved_at > today:
        raise ImproperlyConfigured("Breached-password corpus retrieval date is in the future.")
    if generated_at < retrieved_at or generated_at > today:
        raise ImproperlyConfigured("Breached-password corpus generation date is invalid.")
    if today - retrieved_at > timedelta(days=maximum_age_days):
        raise ImproperlyConfigured(
            "Breached-password corpus is stale; install a reviewed update before continuing."
        )
    return metadata


@lru_cache(maxsize=8)
def _load_breached_password_corpus(
    path_value: str,
    minimum_entries: int,
    maximum_age_days: int,
    maximum_bytes: int,
) -> BreachedPasswordCorpus:
    path = Path(path_value)
    descriptor = -1
    try:
        path_stat = path.lstat()
        if not stat.S_ISREG(path_stat.st_mode):
            raise ImproperlyConfigured(
                "Breached-password corpus path must identify a regular, non-symlink file."
            )
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        file_stat = os.fstat(descriptor)
        if not stat.S_ISREG(file_stat.st_mode) or (
            file_stat.st_dev,
            file_stat.st_ino,
        ) != (path_stat.st_dev, path_stat.st_ino):
            raise ImproperlyConfigured(
                "Breached-password corpus path changed while it was being opened."
            )
        if file_stat.st_size > maximum_bytes:
            raise ImproperlyConfigured(
                "Breached-password corpus exceeds its configured size limit."
            )
        if os.name == "posix" and file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
            raise ImproperlyConfigured(
                "Breached-password corpus must not be writable by its group or other users."
            )
        with os.fdopen(descriptor, "rb") as corpus_file:
            descriptor = -1
            content = corpus_file.read(maximum_bytes + 1)
        if len(content) > maximum_bytes:
            raise ImproperlyConfigured(
                "Breached-password corpus exceeds its configured size limit."
            )
    except ImproperlyConfigured:
        raise
    except OSError as error:
        raise ImproperlyConfigured("Unable to read the breached-password corpus.") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    if not content.startswith(CORPUS_MAGIC):
        raise ImproperlyConfigured("Breached-password corpus header is invalid.")
    metadata_end = content.find(b"\n", len(CORPUS_MAGIC))
    if metadata_end < 0 or metadata_end - len(CORPUS_MAGIC) > MAX_METADATA_BYTES:
        raise ImproperlyConfigured("Breached-password corpus metadata record is invalid.")
    try:
        metadata_value = json.loads(
            content[len(CORPUS_MAGIC) : metadata_end].decode("utf-8"),
            object_pairs_hook=_json_object_without_duplicate_keys,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise ImproperlyConfigured(
            "Breached-password corpus metadata is not valid JSON."
        ) from error
    metadata = _validate_metadata(
        metadata_value,
        minimum_entries=minimum_entries,
        maximum_age_days=maximum_age_days,
    )
    payload = content[metadata_end + 1 :]
    entries = int(metadata["entries"])
    if len(payload) != entries * HASH_RECORD_BYTES:
        raise ImproperlyConfigured(
            "Breached-password corpus entry count does not match its payload."
        )
    if hashlib.sha256(payload).hexdigest() != metadata["payload_sha256"]:
        raise ImproperlyConfigured("Breached-password corpus payload failed its integrity check.")

    previous = b""
    for index in range(entries):
        offset = index * HASH_RECORD_BYTES
        digest = payload[offset : offset + HASH_BYTES]
        if payload[offset + HASH_BYTES : offset + HASH_RECORD_BYTES] != b"\n":
            raise ImproperlyConfigured("Breached-password corpus record delimiter is invalid.")
        try:
            digest_text = digest.decode("ascii")
        except UnicodeDecodeError as error:
            raise ImproperlyConfigured(
                "Breached-password corpus contains a non-ASCII hash."
            ) from error
        if _HEX_40.fullmatch(digest_text) is None or digest <= previous:
            raise ImproperlyConfigured(
                "Breached-password corpus hashes must be uppercase, unique, and sorted."
            )
        previous = digest
    return BreachedPasswordCorpus(metadata=metadata, payload=payload)


def load_breached_password_corpus(
    path: str | Path,
    *,
    minimum_entries: int,
    maximum_age_days: int,
    maximum_bytes: int,
) -> BreachedPasswordCorpus:
    """Read and validate one immutable local corpus."""

    limits = (minimum_entries, maximum_age_days, maximum_bytes)
    if any(isinstance(value, bool) or not isinstance(value, int) or value < 1 for value in limits):
        raise ImproperlyConfigured("Breached-password corpus limits must be positive integers.")
    return _load_breached_password_corpus(
        os.path.abspath(os.fspath(path)),
        minimum_entries,
        maximum_age_days,
        maximum_bytes,
    )


def clear_breached_password_corpus_cache() -> None:
    """Discard cached corpus bytes after a controlled update or during tests."""

    _load_breached_password_corpus.cache_clear()


def validate_breached_password_corpus(
    path: str | Path,
    *,
    minimum_entries: int,
    maximum_age_days: int,
    maximum_bytes: int,
) -> None:
    """Fail settings loading when an explicitly configured corpus is unsafe or stale."""

    load_breached_password_corpus(
        path,
        minimum_entries=minimum_entries,
        maximum_age_days=maximum_age_days,
        maximum_bytes=maximum_bytes,
    )


def _context_skeleton(value: str, *, preserve_numeric_suffix: bool = False) -> str:
    normalized = unicodedata.normalize("NFKC", value).casefold()
    collapsed = "".join(
        character.translate(_LEET_TRANSLATION)
        if not character.isalnum() and character in {"@", "$"}
        else character
        for character in normalized
        if character.isalnum() or character in {"@", "$"}
    )
    suffix_start = len(collapsed)
    if preserve_numeric_suffix:
        while suffix_start and collapsed[suffix_start - 1] in "0123456789":
            suffix_start -= 1
    core = collapsed[:suffix_start].translate(_LEET_TRANSLATION)
    return core + collapsed[suffix_start:]


class ContextSpecificPasswordValidator:
    """Reject product-name permutations that remain easy to guess."""

    def __init__(self, identifiers: list[str] | tuple[str, ...] | None = None) -> None:
        configured = settings.PASSWORD_CONTEXT_IDENTIFIERS if identifiers is None else identifiers
        if (
            not isinstance(configured, (list, tuple))
            or not configured
            or any(not isinstance(identifier, str) for identifier in configured)
        ):
            raise ImproperlyConfigured("Password context identifiers must be non-empty strings.")
        skeletons = {_context_skeleton(identifier) for identifier in configured}
        if "" in skeletons:
            raise ImproperlyConfigured("Password context identifiers must be non-empty strings.")
        alternatives = "|".join(
            re.escape(value) for value in sorted(skeletons, key=len, reverse=True)
        )
        self.pattern = re.compile(
            rf"^(?:my|our|the)?(?:{alternatives})(?:app|home|admin|password)?[0-9]{{0,4}}$"
        )

    def validate(self, password: str, user: Any | None = None) -> None:
        del user
        candidate_skeletons = {
            _context_skeleton(password),
            _context_skeleton(password, preserve_numeric_suffix=True),
        }
        if any(self.pattern.fullmatch(value) is not None for value in candidate_skeletons):
            raise ValidationError(
                _("This password is based on the application name and is too easy to guess."),
                code="password_context_specific",
            )

    def get_help_text(self) -> str:
        return _("Your password cannot be based on the application or system name.")


class OfflineBreachedPasswordValidator:
    """Compare a locally computed full SHA-1 against the packaged offline corpus."""

    def __init__(
        self,
        corpus_path: str | Path | None = None,
        minimum_entries: int | None = None,
        maximum_age_days: int | None = None,
        maximum_bytes: int | None = None,
    ) -> None:
        self.corpus_path = (
            settings.BREACHED_PASSWORD_CORPUS_PATH if corpus_path is None else corpus_path
        )
        self.minimum_entries = (
            minimum_entries
            if minimum_entries is not None
            else settings.BREACHED_PASSWORD_CORPUS_MINIMUM_ENTRIES
        )
        self.maximum_age_days = (
            maximum_age_days
            if maximum_age_days is not None
            else settings.BREACHED_PASSWORD_CORPUS_MAXIMUM_AGE_DAYS
        )
        self.maximum_bytes = (
            maximum_bytes
            if maximum_bytes is not None
            else settings.BREACHED_PASSWORD_CORPUS_MAXIMUM_BYTES
        )

    def validate(self, password: str, user: Any | None = None) -> None:
        del user
        corpus = load_breached_password_corpus(
            self.corpus_path,
            minimum_entries=self.minimum_entries,
            maximum_age_days=self.maximum_age_days,
            maximum_bytes=self.maximum_bytes,
        )
        digest = hashlib.sha1(password.encode("utf-8"), usedforsecurity=False).hexdigest().upper()
        if corpus.contains(digest.encode("ascii")):
            raise ValidationError(
                _("This password has appeared in a known data breach. Choose another password."),
                code="password_breached",
            )

    def get_help_text(self) -> str:
        return _("Your password cannot appear in the application's offline breached-password list.")
