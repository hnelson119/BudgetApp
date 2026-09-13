# File handling policy

This policy is the complete production upload inventory for Household Budget. The application has
one upload feature: authenticated household members may stage a transaction statement through the
transaction CSV import flow. Receipt references are text fields, not attachments. There are no
image, document, archive, compressed-file, email-attachment, or API upload features.

## Permitted upload contract

| Feature | Format and extension | Media type | Maximum size | Structural limits |
| --- | --- | --- | ---: | --- |
| Transaction CSV import | UTF-8 CSV, with an optional UTF-8 BOM; `.csv` only | The browser is asked for `.csv` or `text/csv`, but the client-supplied media type is not trusted | 5 MiB (5,242,880 bytes) | 10,000 non-blank transaction rows, 50 columns, and 1,000 characters per header or cell |

Compressed files and archives are not accepted, so there is no distinct unpacked size. The 5 MiB
limit applies to the complete decoded multipart file payload. Django's request and file memory
limits are pinned to the same boundary, and the parser independently stops reading as soon as the
payload exceeds it.

## Validation and rejected-file behavior

The importer treats the filename and all file content as untrusted. It reduces the supplied name to
a printable basename of at most 255 characters and requires the `.csv` extension. It then reads the
payload through a bounded chunk loop, closes the upload on every accepted or rejected path, rejects
empty or NUL-containing data, decodes UTF-8 strictly, and uses Python's strict CSV parser. Headers
must be present, non-empty, and case-insensitively unique; each populated row must have exactly the
declared number of columns. The configured byte, row, column, and cell limits are enforced before
the file can produce ledger entries.

An invalid, malformed, binary, oversized, archived, or wrongly named upload fails closed with a
validation error. No `ImportBatch` or `ImportRow` is created, no ledger entry is written, and the
application never publishes or redistributes the rejected content. The raw uploaded file is not
stored as an application-managed file and is not available for download.

## End-user processing and download safety

Successfully parsed cells are staged only as bounded database rows for an authenticated,
household-scoped mapping and preview. Django templates escape preview text by default. Users must
explicitly confirm the normalized preview before an atomic ledger commit; abandonment, successful
commit, or the 24-hour stale-import cleanup scrubs staged raw cells.

The application never returns the original upload to an end user. Its only downloadable files are
freshly generated transaction and protected-audit CSV exports. Both are streamed without retaining
a server-side export file, use fixed application-owned headers and filenames, and prefix text whose
first non-space character is `=`, `+`, `-`, or `@` so spreadsheet software treats it as literal
text. Export authorization, household scoping, recent reauthentication, audit-integrity checks, and
the protected audit trail are enforced separately.

Adding an upload feature or expanding the accepted file contract requires security review, updates
to this inventory, explicit byte and unpacked-size limits, content-aware validation, rejected-file
behavior, safe download or rendering behavior, and adversarial tests before release.
