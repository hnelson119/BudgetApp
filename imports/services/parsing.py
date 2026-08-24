from __future__ import annotations

import csv
import hashlib
import io
from dataclasses import dataclass

from django.conf import settings
from django.core.exceptions import ValidationError
from django.core.files.uploadedfile import UploadedFile


@dataclass(frozen=True, slots=True)
class ParsedCSVRow:
    row_number: int
    values: dict[str, str]


@dataclass(frozen=True, slots=True)
class ParsedCSV:
    filename: str
    checksum: str
    headers: tuple[str, ...]
    rows: tuple[ParsedCSVRow, ...]


def _safe_filename(filename: str) -> str:
    normalized = filename.replace("\\", "/").rsplit("/", 1)[-1].strip()
    normalized = "".join(character if character.isprintable() else "_" for character in normalized)
    if not normalized or not normalized.lower().endswith(".csv"):
        raise ValidationError("Upload a file with a .csv extension.")
    return normalized[:255]


def _read_bounded(upload: UploadedFile, maximum_bytes: int) -> bytes:
    payload = bytearray()
    for chunk in upload.chunks(chunk_size=64 * 1024):
        payload.extend(chunk)
        if len(payload) > maximum_bytes:
            raise ValidationError(f"CSV files cannot exceed {maximum_bytes // (1024 * 1024)} MiB.")
    if not payload:
        raise ValidationError("The CSV file is empty.")
    return bytes(payload)


def parse_csv_upload(upload: UploadedFile) -> ParsedCSV:
    maximum_bytes = int(getattr(settings, "CSV_IMPORT_MAX_BYTES", 5 * 1024 * 1024))
    maximum_rows = int(getattr(settings, "CSV_IMPORT_MAX_ROWS", 10_000))
    maximum_columns = int(getattr(settings, "CSV_IMPORT_MAX_COLUMNS", 50))
    maximum_cell_length = int(getattr(settings, "CSV_IMPORT_MAX_CELL_LENGTH", 1_000))
    filename = _safe_filename(upload.name or "")
    try:
        payload = _read_bounded(upload, maximum_bytes)
    finally:
        upload.close()
    if b"\x00" in payload:
        raise ValidationError("The CSV contains unsupported binary content.")
    try:
        text = payload.decode("utf-8-sig", errors="strict")
    except UnicodeDecodeError as error:
        raise ValidationError("CSV files must use UTF-8 encoding.") from error

    try:
        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        raw_headers = next(reader)
        headers = tuple(value.strip() for value in raw_headers)
        if len(headers) < 3:
            raise ValidationError("The CSV must contain at least three columns.")
        if len(headers) > maximum_columns:
            raise ValidationError(f"The CSV cannot contain more than {maximum_columns} columns.")
        if any(not value for value in headers):
            raise ValidationError("Every CSV column must have a header.")
        normalized_headers = tuple(value.casefold() for value in headers)
        if len(set(normalized_headers)) != len(headers):
            raise ValidationError("CSV column headers must be unique.")
        if any(len(value) > maximum_cell_length for value in headers):
            raise ValidationError("A CSV header exceeds the allowed length.")

        rows: list[ParsedCSVRow] = []
        for raw_row in reader:
            if not raw_row or all(not value.strip() for value in raw_row):
                continue
            if len(raw_row) != len(headers):
                raise ValidationError(f"CSV row {reader.line_num} has the wrong number of columns.")
            if any(len(value) > maximum_cell_length for value in raw_row):
                raise ValidationError(f"CSV row {reader.line_num} contains an oversized value.")
            rows.append(
                ParsedCSVRow(
                    row_number=reader.line_num,
                    values=dict(zip(headers, raw_row, strict=True)),
                )
            )
            if len(rows) > maximum_rows:
                raise ValidationError(f"CSV files cannot contain more than {maximum_rows} rows.")
    except csv.Error as error:
        raise ValidationError("The CSV structure or quoting is malformed.") from error
    except StopIteration as error:
        raise ValidationError("The CSV file does not contain a header row.") from error

    if not rows:
        raise ValidationError("The CSV file does not contain any transaction rows.")
    return ParsedCSV(
        filename=filename,
        checksum=hashlib.sha256(payload).hexdigest(),
        headers=headers,
        rows=tuple(rows),
    )
