from __future__ import annotations

import hashlib
import heapq
import json
import os
import re
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import date
from pathlib import Path
from typing import Any, BinaryIO
from urllib.parse import urlsplit

from django.core.management.base import BaseCommand, CommandError, CommandParser

from identity.password_validation import (
    CORPUS_MAGIC,
    MAX_METADATA_BYTES,
    MAX_METADATA_LABEL_CHARS,
    MAX_SOURCE_URL_CHARS,
)

_HEX_40_BYTES = re.compile(rb"^[0-9A-F]{40}$")
_HEX_64 = re.compile(r"^[0-9a-f]{64}$")
_POSITIVE_INTEGER_BYTES = re.compile(rb"^[0-9]+$")
_MAX_SOURCE_LINE_BYTES = 4096


@dataclass(frozen=True)
class _RankedHash:
    """Heap ordering that treats the least prevalent, largest digest as worst."""

    count: int
    digest: bytes

    def __lt__(self, other: _RankedHash) -> bool:
        if self.count != other.count:
            return self.count < other.count
        return self.digest > other.digest


class Command(BaseCommand):
    help = "Build a bounded, hash-only offline breached-password corpus from a trusted local file."

    def add_arguments(self, parser: CommandParser) -> None:
        parser.add_argument("input", type=Path)
        parser.add_argument("output", type=Path)
        parser.add_argument("--input-format", choices=("hibp-sha1", "plaintext"), required=True)
        parser.add_argument("--expected-sha256", required=True)
        parser.add_argument("--source-name", required=True)
        parser.add_argument("--source-url", required=True)
        parser.add_argument("--source-retrieved-at", required=True)
        parser.add_argument("--max-entries", type=int, default=100_000)
        parser.add_argument("--minimum-entries", type=int, default=10_000)
        parser.add_argument("--replace", action="store_true")

    def _validate_options(self, options: dict[str, Any]) -> tuple[Path, Path, date]:
        input_path = Path(os.path.abspath(os.fspath(options["input"])))
        output_path = Path(os.path.abspath(os.fspath(options["output"])))
        expected_sha256 = str(options["expected_sha256"]).lower()
        if _HEX_64.fullmatch(expected_sha256) is None:
            raise CommandError("--expected-sha256 must be one SHA-256 digest.")
        source_url = str(options["source_url"])
        try:
            parsed_source_url = urlsplit(source_url)
            _ = parsed_source_url.port
            valid_source_url = (
                parsed_source_url.scheme == "https"
                and parsed_source_url.hostname is not None
                and parsed_source_url.username is None
                and parsed_source_url.password is None
                and len(source_url) <= MAX_SOURCE_URL_CHARS
                and not any(character.isspace() for character in source_url)
            )
        except ValueError:
            valid_source_url = False
        if not valid_source_url:
            raise CommandError("--source-url must use HTTPS.")
        source_name = str(options["source_name"]).strip()
        if (
            not source_name
            or len(source_name) > MAX_METADATA_LABEL_CHARS
            or not source_name.isprintable()
        ):
            raise CommandError("--source-name is invalid.")
        try:
            retrieved_at = date.fromisoformat(str(options["source_retrieved_at"]))
        except ValueError as error:
            raise CommandError("--source-retrieved-at must be an ISO date.") from error
        if retrieved_at > date.today():
            raise CommandError("--source-retrieved-at cannot be in the future.")
        maximum_entries = options["max_entries"]
        minimum_entries = options["minimum_entries"]
        if (
            isinstance(maximum_entries, bool)
            or not isinstance(maximum_entries, int)
            or isinstance(minimum_entries, bool)
            or not isinstance(minimum_entries, int)
            or minimum_entries < 1
            or maximum_entries < minimum_entries
            or maximum_entries > 500_000
        ):
            raise CommandError("Entry limits must satisfy 1 <= minimum <= maximum <= 500000.")
        if input_path == output_path:
            raise CommandError("Input and output must be different files.")
        try:
            input_stat = input_path.lstat()
        except OSError as error:
            raise CommandError("Input must be a readable, regular, non-symlink file.") from error
        if not stat.S_ISREG(input_stat.st_mode):
            raise CommandError("Input must be a readable, regular, non-symlink file.")
        try:
            output_parent_stat = output_path.parent.lstat()
        except OSError as error:
            raise CommandError(
                "Output parent must be an existing, non-symlink directory."
            ) from error
        if not stat.S_ISDIR(output_parent_stat.st_mode) or output_path.parent.is_symlink():
            raise CommandError("Output parent must be an existing, non-symlink directory.")
        if output_path.is_symlink():
            raise CommandError("Output must not be a symlink.")
        if output_path.exists() and os.path.samefile(input_path, output_path):
            raise CommandError("Input and output must be different files.")
        if output_path.exists() and not options["replace"]:
            raise CommandError("Output already exists; use --replace after reviewing the source.")
        return input_path, output_path, retrieved_at

    @contextmanager
    def _open_source(self, input_path: Path) -> Iterator[BinaryIO]:
        descriptor = -1
        try:
            path_stat = input_path.lstat()
            flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(input_path, flags)
            file_stat = os.fstat(descriptor)
            if not stat.S_ISREG(file_stat.st_mode) or (
                file_stat.st_dev,
                file_stat.st_ino,
            ) != (path_stat.st_dev, path_stat.st_ino):
                raise CommandError("Input changed while it was being opened.")
            with os.fdopen(descriptor, "rb") as source:
                descriptor = -1
                yield source
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _source_lines(
        self,
        source: BinaryIO,
        *,
        source_hash: Any,
    ) -> Iterator[tuple[int, bytes]]:
        line_number = 0
        while True:
            raw_line = source.readline(_MAX_SOURCE_LINE_BYTES + 1)
            if not raw_line:
                return
            line_number += 1
            if len(raw_line) > _MAX_SOURCE_LINE_BYTES:
                raise CommandError(f"Source line {line_number} exceeds the safe length limit.")
            source_hash.update(raw_line)
            yield line_number, raw_line

    def _read_source_line(self, raw_line: bytes, *, line_number: int) -> bytes:
        value = raw_line[:-1] if raw_line.endswith(b"\n") else raw_line
        if value.endswith(b"\r"):
            value = value[:-1]
        if not value:
            raise CommandError(f"Source line {line_number} is empty.")
        return value

    def _hash_plaintext_source(
        self,
        source: BinaryIO,
        *,
        maximum_entries: int,
        source_hash: Any,
    ) -> set[bytes]:
        selected: set[bytes] = set()
        for line_number, raw_line in self._source_lines(source, source_hash=source_hash):
            value = self._read_source_line(raw_line, line_number=line_number)
            try:
                password = value.decode("utf-8")
            except UnicodeDecodeError as error:
                raise CommandError(f"Source line {line_number} is not valid UTF-8.") from error
            if line_number > maximum_entries:
                continue
            digest = (
                hashlib.sha1(password.encode("utf-8"), usedforsecurity=False)
                .hexdigest()
                .upper()
                .encode("ascii")
            )
            selected.add(digest)
        return selected

    def _select_hibp_hashes(
        self,
        source: BinaryIO,
        *,
        maximum_entries: int,
        source_hash: Any,
    ) -> set[bytes]:
        selected: list[_RankedHash] = []
        for line_number, raw_line in self._source_lines(source, source_hash=source_hash):
            value = self._read_source_line(raw_line, line_number=line_number)
            try:
                digest, count_value = value.split(b":", maxsplit=1)
                if _POSITIVE_INTEGER_BYTES.fullmatch(count_value) is None:
                    raise ValueError
                count = int(count_value)
            except (ValueError, TypeError) as error:
                raise CommandError(
                    f"Source line {line_number} is not a HASH:COUNT record."
                ) from error
            if _HEX_40_BYTES.fullmatch(digest) is None or count < 1:
                raise CommandError(f"Source line {line_number} has an invalid hash or count.")
            ranked = _RankedHash(count=count, digest=digest)
            if len(selected) < maximum_entries:
                heapq.heappush(selected, ranked)
                continue
            worst = selected[0]
            if count > worst.count or (count == worst.count and digest < worst.digest):
                heapq.heapreplace(selected, ranked)
        hashes = {entry.digest for entry in selected}
        if len(hashes) != len(selected):
            raise CommandError("The selected HIBP records contain duplicate hashes.")
        return hashes

    def _write_corpus(
        self,
        *,
        output_path: Path,
        hashes: set[bytes],
        metadata: dict[str, Any],
    ) -> None:
        payload = b"".join(digest + b"\n" for digest in sorted(hashes))
        metadata["payload_sha256"] = hashlib.sha256(payload).hexdigest()
        metadata_record = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
        if len(metadata_record) > MAX_METADATA_BYTES:
            raise CommandError("Corpus metadata exceeds the safe length limit.")
        temporary_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb",
                prefix=f".{output_path.name}.",
                dir=output_path.parent,
                delete=False,
            ) as temporary:
                temporary_name = temporary.name
                temporary.write(CORPUS_MAGIC)
                temporary.write(metadata_record + b"\n")
                temporary.write(payload)
                temporary.flush()
                os.fsync(temporary.fileno())
            os.chmod(temporary_name, 0o644)
            os.replace(temporary_name, output_path)
        except OSError as error:
            if temporary_name:
                Path(temporary_name).unlink(missing_ok=True)
            raise CommandError("Unable to install the corpus atomically.") from error

    def handle(self, *args: Any, **options: Any) -> None:
        del args
        input_path, output_path, retrieved_at = self._validate_options(options)
        source_hash = hashlib.sha256()
        try:
            with self._open_source(input_path) as source:
                if options["input_format"] == "plaintext":
                    hashes = self._hash_plaintext_source(
                        source,
                        maximum_entries=int(options["max_entries"]),
                        source_hash=source_hash,
                    )
                    selection = f"first-{int(options['max_entries'])}-source-order"
                else:
                    hashes = self._select_hibp_hashes(
                        source,
                        maximum_entries=int(options["max_entries"]),
                        source_hash=source_hash,
                    )
                    selection = f"top-{int(options['max_entries'])}-by-breach-count"
        except OSError as error:
            raise CommandError("Unable to read the source corpus.") from error

        if source_hash.hexdigest() != str(options["expected_sha256"]).lower():
            raise CommandError("Source SHA-256 did not match; no corpus was written.")
        if len(hashes) < int(options["minimum_entries"]):
            raise CommandError(
                f"Source produced {len(hashes)} unique entries; "
                f"at least {int(options['minimum_entries'])} are required."
            )

        metadata = {
            "corpus_version": 1,
            "entries": len(hashes),
            "generated_at": date.today().isoformat(),
            "selection": selection,
            "source_name": str(options["source_name"]).strip(),
            "source_retrieved_at": retrieved_at.isoformat(),
            "source_sha256": source_hash.hexdigest(),
            "source_url": str(options["source_url"]),
        }
        self._write_corpus(output_path=output_path, hashes=hashes, metadata=metadata)
        self.stdout.write(
            self.style.SUCCESS(
                f"Installed {len(hashes)} hash-only breached-password records at {output_path}."
            )
        )
