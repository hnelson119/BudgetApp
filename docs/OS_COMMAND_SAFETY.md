# Operating-system command safety

Status: implemented; release verification pending
Last reviewed: 2026-09-13

## Boundary

The production Python runtime launches no child processes and invokes no operating-system shell.
Request fields, route values, account and household data, financial records, CSV imports, filenames,
configuration values, and database content therefore have no path to command syntax or process
arguments. Application work stays inside Python, Django, PostgreSQL, bounded filesystem APIs, and
the local Unix datagram logging channel.

This zero-execution rule covers every application package, configuration and startup module,
migration, management command, and `manage.py`. The production image contains only those reviewed
runtime roots. Compose starts each service with repository-owned fixed argument arrays or fixed
entry-point scripts; an end user cannot alter deployment commands.

Deployment, backup, restore, certificate, and security-test scripts are trusted operator tooling,
not request-reachable application code. They accept only documented administrator inputs and remain
subject to their existing strict validation and least-privilege container boundaries. No user or
financial data may be forwarded to those tools.

## Enforced rules

`scripts/check_os_command_safety.py` parses every Python file in the 15 production runtime roots,
including migrations, plus `manage.py`. It fails closed on:

- `subprocess`, `multiprocessing`, `pty`, legacy `commands`, or `ctypes` imports, including aliases;
- `os.system`, `os.popen`, every `os.exec*` or `os.spawn*` variant, `posix_spawn`, `fork`, and
  platform shell-association APIs;
- asyncio child-process creation;
- direct or aliased imports and references to tracked process APIs, and wildcard imports from
  process-capable runtime namespaces;
- dynamic module loading through `__import__` or `importlib.import_module`; and
- dynamic lookup of `os` or `asyncio` members that could hide a launch API.

Fixed lookup of a known non-process portability API, such as `getattr(os, "getuid", None)`, remains
allowed. Database methods named `execute` are not operating-system execution and are intentionally
outside this rule.

The checker inventories recognized imports, direct calls, and direct API references. It is not
whole-program analysis: arbitrary object indirection, reflection, extension modules, and new
execution mechanisms still require source review. A passing inventory alone is not an operating-
system sandbox or a guarantee about unreviewed dependencies.

If a future feature genuinely requires a child process, it needs a dedicated design review, a fixed
executable path, an argument list with no shell, strict per-argument allowlists and length bounds, a
minimal environment and working directory, time and resource limits, safe output handling, and
adversarial tests. The checker and this policy must be updated explicitly; a generic exception is
not acceptable.

## Verification

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_os_command_safety.py
.\.venv\Scripts\python.exe -m pytest tests\test_os_command_safety.py
```

The tests accept the complete production runtime, verify its roots and both quality-gate entry
points, and prove rejection of process modules, renamed imports, OS execution calls, asynchronous
shell creation, dynamic imports, and dynamic API lookup. This implements the repository-deliverable
portion of ASVS `v5.0.0-1.2.5`; a dated release-candidate run remains pending.
