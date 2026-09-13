# Canonical input-decoding boundary

Status: implemented; release verification pending
Last reviewed: 2026-09-13

Each encoded input is decoded or parsed exactly once at the boundary where that encoding is
expected. Validation, authorization, business rules, and persistence operate on the resulting
canonical value. Application code never performs a second percent, HTML-entity, query-string,
Unicode-escape, or general-purpose Base64 decoding pass over framework-decoded input.

## Reviewed boundaries

| Input | One decoding or parsing path | Validation after canonicalization |
| --- | --- | --- |
| HTTPS path, query, and form input | Django's request parser performs the framework-owned percent and form decoding. | Routing, forms, field validators, household authorization, and services receive the canonical string. There is no application `unquote`, `unquote_plus`, `parse_qs`, or `parse_qsl` pass. |
| CSV upload | Bounded bytes decode once as strict `utf-8-sig`, intentionally accepting one optional UTF-8 BOM, before the standard CSV parser runs once. | Binary NUL rejection precedes decoding; header, shape, row, column, cell, mapping, type, duplicate, and business validation use the parsed strings. Invalid bytes never use replacement or ignored-error behavior. |
| Security-log datagram | One strict UTF-8 byte decode followed by one JSON parse. | The isolated collector then requires the exact object shape, stream, logger, timestamp, types, field allowlist, size limits, redaction, and event syntax before archiving. |
| Security alert archive | The protected file is read as strict UTF-8 and each bounded line is parsed as JSON once. | Review rejects unexpected fields, values, timestamps, event syntax, file type, symlinks, ownership, permissions, and excessive size. Parsed fields are never decoded again. |
| Signed audit checkpoint | The bounded file is read as strict UTF-8 and parsed as JSON once. | The verifier rejects path input, validates the signature and exact document structure, converts typed identifiers once, then compares the complete database chain and head. |
| MFA encrypted seed record | Authenticated Fernet decryption produces one JSON byte payload that `json.loads` interprets once. | Version, user binding, type, key version, and ciphertext authentication are checked before use. Locally generated Base32 TOTP secrets have one purpose-specific Base32 decoding operation for HMAC input. |
| MFA generated output | Fernet tokens, locally generated Base32 secrets, and QR SVG bytes use strict default UTF-8 decoding only to create their application strings; QR data is Base64-encoded for output. | Values originate from the CSPRNG or reviewed renderer, have fixed consumers, and are not reinterpreted as user-supplied markup or paths. |
| Offline password corpus | Bounded metadata bytes decode once as strict UTF-8 then parse as JSON once; each fixed-length hash record decodes once as strict ASCII. The trusted builder decodes each source line once as strict UTF-8. | Exact metadata fields, dates, counts, checksum, length, delimiters, uppercase SHA-1 syntax, sort order, uniqueness, source URL policy, and freshness are validated before membership use or packaging. |
| Synthetic pentest fixture | The repository fixture is read once as ASCII and parsed as JSON once. | Exact synthetic schema and value constraints are applied before the disposable security harness uses it. No production data is accepted. |

Calls such as `urlsplit` are structural parsers, not percent decoders. They validate already
canonical local URLs or trusted build metadata and never cause a network request. JSON parsing is
included in the machine inventory because a second deserialization pass could create the same kind
of validation-order defect even though it is not character decoding.

## Rejected patterns

Production code cannot introduce:

- HTML-entity unescaping or manual percent/query decoding;
- `codecs.decode`, Unicode-escape interpretation, permissive replacement, ignored decode errors, or
  a dynamically selected character encoding;
- general Base16, Base64, Base85, or URL-safe Base64 input decoding;
- an unreviewed `json.load` or `json.loads` call, including nested double parsing; or
- an additional `.decode()` operation, decoder file, or call count without updating this reviewed
  boundary and its adversarial tests.

The only accepted text encodings are strict ASCII, UTF-8, and the CSV-specific UTF-8-with-optional-
BOM form. Encoded, encrypted, hashed, masked, or compressed sensitive values retain the protection
level defined in `docs/DATA_CLASSIFICATION.md`; parsing or decoding never declassifies data.

## Verification

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_canonical_decoding.py
.\.venv\Scripts\python.exe -m pytest tests\test_canonical_decoding.py tests\test_csv_imports.py tests\test_password_policy.py tests\test_security_log_archive.py
```

The checker scans all 219 production Python files, pins the seven files and 16 operations that
decode text, parse JSON, or perform the one approved Base32 conversion, and rejects unsafe aliases
as well as direct calls. Tests prove Django decodes percent-encoded request values once, a nested
JSON parse changes the inventory, only strict literal encodings are accepted, and every prohibited
decoder fails closed. This implements ASVS `v5.0.0-1.1.1`.
