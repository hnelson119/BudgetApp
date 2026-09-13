# Template injection safety

Status: implemented; release verification pending
Last reviewed: 2026-09-13

## Boundary

Application code selects only repository-owned Django templates by fixed literal name. Request,
account, household, imported, financial, and other runtime values may be passed as template context
data, but they must never choose a template, contribute template source, or alter an inheritance or
include path. Django's normal HTML escaping remains the separate output-encoding boundary for
those context values; it does not validate JavaScript, CSS, or URL schemes.

Runtime template construction is prohibited. Production code must not instantiate a template from
a string or call an engine's `from_string` method, even when the current caller believes the string
is trusted. Rendering uses the configured Django template backend and files packaged in the
reviewed application image.

Template files may extend or include another template only through a quoted literal name that
resolves within the production template inventory. Dynamic inheritance, dynamic includes, filters
that alter a dependency name, absolute paths, traversal segments, backslashes, and missing files
are rejected.

## Enforced rules

`scripts/check_template_safety.py` parses every non-migration Python file in the 14 production
application roots and inventories every HTML file in all nine production template roots. It checks
Django's shortcut renderer, loader functions, and template-response classes. Each selection must
use an existing literal name; fallback sequences must contain only existing literals. Aliases of
tracked selection functions are prohibited so the inventory cannot be bypassed by renaming an
import.

The same checker scans every `{% extends %}` and `{% include %}` dependency. Each dependency must be
a quoted literal path present in the inventory. Direct `Template` construction, `Engine` imports,
and any `from_string` call are prohibited. New template roots, selection mechanisms, or engines
require an explicit policy and checker update before they can pass review.

Both local quality gates and pull-request CI run the checker. The inventory reports reviewed
template, server-side selection, and dependency counts so any boundary change is visible in review.
This direct-API inventory does not prove safety under arbitrary callable reassignment, reflection,
custom template tags, or dynamically loaded engines. Those changes still require source review.

## Verification

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_template_safety.py
.\.venv\Scripts\python.exe -m pytest tests\test_template_safety.py
```

The tests accept the complete production surface and prove rejection of dynamic and missing render
targets, runtime template construction, renamed selection APIs, mixed fallback lists, dynamic
inheritance and includes, filtered dependency names, and missing dependencies. This implements the
repository-deliverable portion of ASVS `v5.0.0-1.3.7`; a dated release-candidate run remains
pending.
