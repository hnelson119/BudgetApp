# JavaScript and JSON output encoding

Status: implemented; release verification pending
Last reviewed: 2026-09-17

## Boundary

The browser receives dynamic application pages through Django templates with automatic HTML
escaping enabled. This is not JavaScript, CSS, or URL-scheme validation. Templates must not disable
auto-escaping, mark dynamic values safe, or
construct executable inline scripts. The content security policy independently permits scripts only
from same-origin external files and forbids object execution.

Production JavaScript constructs elements with DOM APIs and inserts dynamic text through
`textContent` or safe element properties. It must not pass data into HTML-parsing sinks, event
handler attributes, string-evaluated timers, `eval`, or the `Function` constructor. A future feature
that needs reviewed rich HTML requires a dedicated sanitizer, adversarial tests, and an explicit
update to this policy and its inventory; a template `safe` filter is not an acceptable substitute.

The only JSON HTTP responses are the fixed, minimal liveness and readiness objects in
`core/views.py`. Both use Django `JsonResponse` with its default encoder so string data is encoded as
JSON data rather than executable syntax. Production code must not hand-build JavaScript or JSON
response bodies, select a custom `JsonResponse` encoder, or return JavaScript or JSON through a raw
`HttpResponse` media type.

Server-side `json.dumps` calls used for protected logs, audit data, backup metadata, or other files
are not inserted into a browser document. They remain subject to their separate format, integrity,
and redaction controls and do not weaken this browser-output boundary.

## Enforced rules

`scripts/check_output_encoding.py` inventories every HTML and JavaScript file in the production
client surface and every non-migration Python file in the 14 production application roots. It
rejects recognized direct uses of:

- template auto-escaping bypasses, trusted `safe` filters, and inline executable scripts;
- JavaScript HTML-parsing, dynamic code-execution, string-timer, and event-handler sinks;
- custom trusted-HTML methods or calls to Django's `mark_safe`, `SafeString`, or `SafeText` APIs;
- literal JavaScript or JSON response media types outside the reviewed response helper; and
- custom `JsonResponse` encoders, positional overrides, and opaque keyword expansion.

The checker records the number of reviewed templates, scripts, and default-encoder JSON responses.
An inventory change therefore requires code review and corresponding test or policy updates. Both
local quality gates and pull-request CI run the checker.

This direct-API inventory is not a JavaScript parser or whole-program data-flow proof. Computed
property names, callable reassignment, dynamically assembled source, and new template contexts
still require review; the patterns do not replace contextual encoding, CSP, or browser testing.

## Verification

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_output_encoding.py
.\.venv\Scripts\python.exe -m pytest tests\test_output_encoding.py tests\test_logging.py
```

The tests accept the production inventory, confirm both quality-gate entry points, and prove that
representative template bypasses, script sinks, trusted-HTML APIs, manually typed JSON responses,
and custom JSON encoders are rejected. This implements the repository-deliverable portion of ASVS
`v5.0.0-1.2.3`; a dated release-candidate run remains pending.
