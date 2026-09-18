# Dangerous-context sanitization policy

Status: implemented boundary; release verification pending
Last reviewed: 2026-09-13
Next review due: 2026-12-12

## Rule

Every value entering a potentially dangerous interpreter or output context must receive the safe
treatment for that exact context immediately before the sink. The application uses parameterized
APIs, contextual encoding, redaction, strict allowlists, or complete feature absence. It does not
try to make a value universally safe with one generic input filter.

This policy implements OWASP ASVS 5.0.0 `v5.0.0-1.3.3`. Its machine-readable source is
`docs/context-sanitization.json`, validated by `scripts/check_context_sanitization.py` in both normal
quality gates.

## Reviewed contexts

Eleven context families are in scope:

- Django HTML and browser JavaScript use template auto-escaping and DOM `textContent`; HTML parsing,
  inline scripts, dynamic code execution, and custom trusted-HTML APIs are prohibited.
- Database work uses Django's ORM. The three application `cursor.execute` calls contain literal
  SQL; two pass data separately as driver parameters and the third is a fixed readiness query. The
  22 schema-editor calls execute fixed module-level migration literals and receive no untrusted
  data.
- Server template names and dependencies are fixed existing literals.
- Regular-expression patterns are literals except for one reviewed alternation whose configured
  values are independently `re.escape` encoded.
- Production request and management code has no child-process or shell execution API.
- Python formatting, datetime, logging, and CSV date grammars are code-owned literals.
- Redirect and notification action URLs are restricted to their same-origin or exact approved HTTPS
  context, with no malformed, downgraded, backslash, or second-decoding path.
- Transaction and audit CSV text cells receive spreadsheet-formula neutralization immediately
  before `csv.writer`.
- Logging uses code-owned messages, bounded pseudonymous fields, and recursive redaction. It rejects
  attacker-selected destinations and excludes bodies, queries, paths, secrets, financial content,
  raw object identifiers, and exception text.
- Filesystem access is not request-selectable. Trusted operator filenames and paths are constrained
  to configured roots or normalized explicit paths, with traversal, symlink, exclusive-open, and
  basename checks appropriate to the operation.
- Hardened production sends no email and uses the dummy backend, so no untrusted header or protocol
  command reaches SMTP or IMAP.

## Enforcement and change control

The aggregate checker statically scans every production Python file, including migrations, for raw
SQL APIs. A new call, dynamic SQL text, or changed parameterization inventory fails closed. It also requires the nine
specialized output, template, command, format, regex, logging, communication, input-validation, and
authorization checks to remain wired into both platform gates, and pins the CSV, redirect,
notification action, checkpoint filename, email, and log-redaction source contracts.

All upstream structure and length validation remains defined in `docs/INPUT_VALIDATION_POLICY.md`.
That validation controls data quality and resource use; the context treatment here prevents the
validated value from acquiring executable or structural meaning at a later sink. A value reused in
two contexts must receive two context-specific treatments.

The application maintainer owns this policy. Review is required at least every 90 days and before
adding a raw query, renderer, browser sink, template loader, pattern, process API, formatter,
redirect, export format, log field, filesystem operation, upload type, or communication transport.
New contexts must be added to the catalog and a fail-closed source check before release.

This is implementation evidence, not a release pass. A dated release-candidate adversarial run and
sanitized retained evidence are still required before the ASVS requirement is marked verified.
