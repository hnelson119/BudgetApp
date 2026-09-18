# Format-string safety

Status: implemented; release verification pending
Last reviewed: 2026-09-13

## Boundary

Format strings and format specifications are application code, never request or stored data.
Runtime account, household, financial, CSV, route, and configuration values may fill a fixed
placeholder, but they must not define placeholders, conversion flags, attribute lookups, widths,
precision, date directives, HTML format structure, or log-message grammar.

Literal Python f-strings are safe at this boundary because their grammar is fixed in source and
runtime values occupy only compiled expression slots. Their format specifications must also be
literal. Literal `str.format` templates and the built-in `format` function with a literal
specification are permitted; a dynamic receiver or specification is not.

The CSV importer is the sole reviewed dynamic date-format loop. The selected form value indexes an
exact code-owned dictionary, and each resulting format is one of four fixed date grammars. Unknown
selection values fail validation before parsing. The dictionary and the exact `strptime` call are
pinned by the inventory.

Structured log messages remain fixed literals. Runtime context belongs only in allowlisted `extra`
fields, where the central formatter applies type restrictions and redaction. The logging handler's
single `self.format(record)` call invokes the configured formatter on a `LogRecord`; it does not
interpret runtime data as a formatting grammar and is pinned as a reviewed non-string method.

## Enforced rules

`scripts/check_format_string_safety.py` parses every Python file in the 15 production runtime roots,
including migrations, plus `manage.py`. It fails closed on:

- dynamic `str.format` or `format_map` receivers and aliased formatting helpers;
- non-literal built-in format specifications or nested dynamic specifications in f-strings,
  literal `str.format`/`format_map` templates, and HTML-format strings;
- non-literal Django HTML-format strings and joins;
- non-literal `strftime` grammars and unreviewed dynamic `strptime` grammars;
- `string.Template` and `string.Formatter` runtime grammars;
- non-literal structured-logger message templates; and
- any percent operator outside the exact reviewed numeric-modulo inventory.

The 11 current percent operators are arithmetic used for calendar recurrence, TOTP arithmetic, and
synthetic test-data scheduling. Their file, normalized expression, and occurrence count are pinned;
Python percent string formatting has no production exception. Database `%s` placeholders are
literal parameterized-query syntax, not Python percent operations, and remain protected by the SQL
injection boundary.

If a new formatter is needed, keep its grammar literal or define a small exact allowlist selected
only after validating a bounded identifier. Never accept a user-provided format string and attempt
to repair it by removing characters. Add focused adversarial tests and an explicit inventory update
for every reviewed exception.

This direct-API inventory is not whole-program analysis. Callable reassignment, reflection, custom
formatters, and mutation of reviewed allowlists still require source review; matching an exception's
expression is not data-flow proof. Fixed grammar also does not replace bounds on input or output size.

## Verification

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_format_string_safety.py
.\.venv\Scripts\python.exe -m pytest tests\test_format_string_safety.py tests\test_csv_imports.py
```

The tests accept the production inventory and prove rejection of dynamic Python, f-string, percent,
datetime, HTML, string-template, and log grammars, including aliases and a modified CSV allowlist.
This implements the repository-deliverable portion of ASVS `v5.0.0-1.3.10`; a dated
release-candidate run remains pending.
