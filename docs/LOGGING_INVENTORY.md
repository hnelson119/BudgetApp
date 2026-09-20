# Logging inventory and maintenance

Status: inventory and separate security archive implemented; release verification pending
Inventory reviewed: 2026-09-18
Next scheduled review: 2026-12-17

## Purpose and authority

`docs/logging-inventory.json` is the canonical machine-readable inventory of logging at every layer
of the current application stack. It records events, formats, destinations, operational uses,
reader boundaries, retention, sensitive-data rules, integrity/availability properties, and known
limitations. This runbook explains maintenance and release review.

Together they implement the repository-deliverable portions of ASVS `v5.0.0-16.1.1`,
`v5.0.0-16.2.3`, `v5.0.0-16.3.2`, and `v5.0.0-16.4.3`. They do not claim a release-candidate pass.
Production sends a second copy of each Django security record through a permission-restricted Unix
datagram socket to a separate, networkless collector and collector-only archive volume. The
application cannot mount or read that archive. Live retention, alert review, escalation, and
failure observations remain release work.

The release owner reviews the inventory at least every 90 days, on every release candidate, and
whenever a producer, event, format, destination, reader, retention rule, stack layer, provider,
security finding, incident need, cryptographic control, or data classification changes. The quality
gate fails after the recorded review becomes overdue.

Never commit raw runtime, browser, host, provider, database, Docker, security-test, or CI logs. They
may contain restricted identifiers or diagnostics even when the application formatter is defensive.
Retain only the sanitized finding, bounded pass/fail result, candidate commit, date, tester role,
scope, and supersession data allowed by the relevant evidence schema.

## Layer summary

| Layer | Events and format | Destination and access | Retention |
| --- | --- | --- | --- |
| Django operational | Request completion, unhandled exceptions, management/runtime messages; redacting JSON | stdout/stderr to Docker local driver; deployment administrators | 20 MiB × 5 files per container; elapsed time varies |
| Django security | Authentication, authorization denial, MFA/recovery, session, rejected import, and sensitive export outcomes; tagged redacting JSON | Docker copy plus restricted Unix datagrams to the separate archive | Docker copy rotates at 20 MiB × 5; archive minimum 90 days |
| Security archive | Independently validated/redacted security records and six fixed collector diagnostics | Networkless UID 10003 collector; collector-only volume; warning-or-higher alert queue | Persistent volume, minimum 90 days plus incident holds |
| Protected household audit | 83 stable financial/security action IDs; canonical hash-chained rows | `budget_audit` schema plus off-VM signed checkpoints; household/recent-auth, append-only runtime, and audit-reader roles | Live application lifetime; backups retain 7 daily, 4 weekly, 12 monthly |
| Maintenance | 35 backup, restore, Restic, and synthetic database-rotation outcomes; fixed JSON | Docker local plus systemd job lifecycle; deployment administrators | Docker capacity bound; host policy 30 days |
| Gunicorn | Process lifecycle/errors and captured app output; text/JSON | Docker local; deployment administrators | 20 MiB × 5 files; access log disabled |
| nginx relay | Warning/error and process lifecycle text | Docker local; deployment administrators | 20 MiB × 5 files; access log disabled |
| PostgreSQL | Server lifecycle/recovery/errors under pinned defaults; text stderr | Docker local; deployment administrators | 20 MiB × 5 files; statement-wide logging disabled |
| Docker storage | All 13 production service stdout/stderr | VM-local Docker-managed files; root-equivalent Docker readers | Approximately 100 MiB per service, oldest-first rollover |
| Host journal | Timers, Docker, SSH/sudo, UFW, and Tailscale daemon records | Persistent VM journal; root/minimum journal readers | Required 30 days; verify live setting per release |
| Tailscale | Local daemon events and provider configuration changes; optional flow metadata | Device/VM logs and provider service; tailnet administrators/scoped API readers | Configuration audit 90 days; optional flow logs 30 days |
| GitHub Actions | Workflow/check lifecycle and synthetic test output | GitHub repository Actions service; repository-authorized readers | Current repository setting 90 days |
| Browser client | Deliberately opened local diagnostics only; no analytics/telemetry | Volatile approved-device browser profile | Diagnostic session only; delete captures after sanitization |
| Security-test output | Tool-native raw reports and sanitized evidence | Ignored/disposable paths and CI; sanitized findings in Git | Raw through triage, CI 90 days, sanitized Git history durable |

The JSON inventory is authoritative for exact language. Its five event groups are generated from
source literals and validated against the repository: 2 Django operational events, 35 Django
security events, 6 security-archive diagnostics, 83 protected audit actions, and 35 structured
maintenance events. Adding, removing, or renaming a literal event without updating the inventory
fails the local and CI gate.

## Application record contract

Django emits single-line UTF-8 JSON. Each record contains UTC timestamp, level, logger, operational
or security stream, environment, release, request/actor/household correlation IDs, a redacted fixed
message, and only allowlisted structured fields. Exception records include the exception type and
source filename/line/function frames, never exception text. The request logger records method,
resolved route name, response status, and duration; it excludes successful health probes and never
records raw path, query, body, headers, address, or user agent.

Every explicit 403 response emits one warning-level `authorization.denied` security event. Because
object-level authorization intentionally conceals existence with 404, the same event is emitted for
an authenticated, resolved route with identifier arguments that returns 404. The record contains
only method, resolved route name, status, error reference, and the bound pseudonymous context; it
does not contain the URL, query, route arguments, object identifiers, or exception text. Expected
permission and not-found exceptions are not also classified as unhandled application errors.

Authentication and recovery outcome records preserve only two additional typed booleans:
`accepted` and `rate_limited`. These distinguish accepted recovery from rejected submissions and
ordinary failures from active throttling without recording a submitted identity, credential, or
throttle key. The collector rejects non-boolean values for either field.

Every invalid submitted CSV upload, mapping, commit, or abandonment form now emits the same
warning-level rejection event as its corresponding service-level validation failure. The event
contains only its fixed identifier and, for an existing staged batch, its import reference;
submitted form values, filenames, CSV cells, and validation messages are never logged. Each
rejected request emits one event, including when the browser response is a normal form page or
redirect rather than an HTTP error.

Rejected expense, income, card-payment, card-refund, and transaction-reversal submissions follow
the same rule. Invalid forms and service-level business-rule failures emit exactly one fixed
warning event with the HTTP method and request error reference. Financial amounts, descriptions,
notes, reasons, account or entry references, form errors, and submitted values are excluded.

Rejected goal creation, revision, status, contribution, reserve-allocation, and priority-allocation
submissions also follow that minimized rule. Goal names, amounts, dates, statuses, notes, reasons,
account, goal, or period references, preview fingerprints, form errors, and submitted values are
excluded from the security record.

The formatter redacts credential assignments, bearer material, email addresses, and long payment-
card-like numbers. Producers must still minimize before logging: do not rely on redaction to make an
unsafe message acceptable. Passwords, TOTP seeds/codes, recovery codes, sessions/cookies, CSRF
tokens, database/backup keys, raw CSV cells/files, financial values, private addresses/hostnames, and
real security payloads are prohibited from operational and security logs.

The production security handler sends the already-redacted JSON as one bounded datagram. If the
socket is unavailable or a record is oversized, it writes only the fixed
`security.archive.delivery_failed` diagnostic to local stderr; it never echoes the rejected record
or exception. The collector accepts only the security stream, approved logger and field sets, UTC
timestamps, stable event identifiers, and bounded sizes, then applies redaction again before an
append-only, mode-0600, fsynced write. Warning-or-higher records also create a minimized alert row.
Unknown, malformed, unsafe, or unapproved records are rejected with a fixed local diagnostic.

The inventory validator also enforces the destination allowlist. Django may use only the documented
console, null, and security-archive handlers and their fixed logger routes. Application logger names
must be literal and reviewed. Additional settings mutations and file, network, mail, syslog, queue,
dynamic, or third-party telemetry handlers fail the gate. Separate deployment checks pin Docker's
local driver, disabled Gunicorn access logging, nginx stderr-only errors, and the collector socket
and archive isolation. Any intended destination change therefore requires an inventory update and
review in the same change.

The protected audit stream is different from an operational log. It intentionally retains the
minimum authorized financial before/after facts and bounded reason needed for household
accountability, while rejecting credential/session fields. Its append occurs transactionally with
the domain change, PostgreSQL runtime access is append-only through a controlled function, and
hash-chain/checkpoint verification detects modification. Do not route audit payloads into stdout.

## Retention and preservation

Every production Compose service uses the Docker local driver with `max-size: 20m` and
`max-file: 5`. This is a capacity policy, not a time guarantee: noisy services roll over sooner.
Release review measures whether the available window is adequate for the household threat model.
Do not enlarge local retention without checking VM disk capacity and privacy impact.

The separate `security_log_archive` volume survives collector replacement and is not mounted by the
web container. Retain it for at least 90 days and preserve it before rebuild, incident containment,
or volume cleanup. The collector does not silently delete archived records; the release owner must
review capacity and may remove expired data only after the minimum window and any incident hold.
Do not use `docker compose down --volumes` on the deployed project as routine maintenance.

The Linux VM policy requires 30 days of persistent journal history within a documented size cap.
Because the repository does not own host-wide journald configuration, the release owner records the
effective retention, disk cap, reader group, and oldest available timestamp on the selected VM.
Tailscale's provider configuration audit remains available for 90 days; optional network flow logs,
if deliberately enabled, remain available for 30 days. GitHub Actions is currently configured for
90-day artifact/log retention, but durable release decisions live in sanitized committed evidence.

Before rotation, rebuild, containment, or destructive incident work, preserve the exact required raw
window to restricted incident storage. Record only a sanitized summary in Git. A legal/incident hold
supersedes normal rollover; document its owner, scope, access, and eventual destruction outside this
repository. Audit rows/checkpoints are application-lifetime records, and encrypted backup copies
follow the documented daily/weekly/monthly retention.

## Review procedure

1. Run `python scripts/check_logging_inventory.py`. The validator compares the event catalog to
   Python AST literals and structured maintenance shell calls, pins Django handlers, routes, and
   logger names, rejects undocumented sink types or settings mutations, checks all 13 production
   Compose logging policies, validates evidence and retention fields, rejects exact private
   hostnames and embedded credential/key material, and enforces the 90-day review date.
2. Search every application and deployment source for new loggers, stdout/stderr writes, audit
   actions, shell diagnostics, access logs, database logging settings, timer units, provider logs,
   browser telemetry, analytics, CI output, and report/artifact uploads. Every current stack layer
   must map to one inventory record.
3. For each event change, confirm its operational purpose, stable identifier, safe format,
   destination, readers, retention, and prohibited data before updating the catalog. Do not hide an
   unexpected event by broadening a description.
4. On the selected Linux VM, inspect Docker's effective driver/options for every service, the
   collector UID/capabilities/network/mounts/file modes and volume capacity, journald
   persistence/retention/size/readers, nginx/Gunicorn/PostgreSQL logging settings, timer results,
   Tailscale/SSH/UFW events, available history, disk pressure, and time synchronization. Store only
   sanitized pass/fail evidence.
5. Confirm the GitHub Actions retention setting and Tailscale provider terms have not changed.
   Optional flow logging requires an explicit household privacy and plan decision; never assume it
   is enabled.
6. Attempt representative credential, email, long-number, financial, exception, import, and request
   payload leakage against a synthetic production-derived target. Confirm security stream tagging,
   JSON encoding, separate archive delivery, secondary redaction, alert creation, safe malformed-
   record rejection, safe transport failure, request correlation, no raw access logs, and no raw
   security report in Git.
7. Run the minimized alert review and treat every nonzero result as requiring documented triage:

   ```bash
   docker compose exec -T security-log python -m core.security_log_collector review
   ```

   The command reports only counts by level and stable event ID. Preserve the archive, correlate
   restricted raw records by request ID, and follow `docs/INCIDENT_RESPONSE.md` for containment and
   escalation. Never paste raw archive lines into tickets, chat, Git, or release evidence.
8. Review the remaining host-journal and optional provider-flow gaps without treating a local
   implementation run as release verification.
9. Set `inventory_updated` to the review date and `next_review_due` to exactly 90 days later. Update
   this runbook's dates, run the full quality gate, and obtain security review.

## Access and incident rules

Docker, the separate archive, and host journals are restricted to deployment administrators; Docker
group membership is root-equivalent. Household application users have no operational-log access.
They may see only household-scoped audit summaries, with recent password-plus-MFA verification
required for detailed audit access and export. The runtime database role can append through the
controlled function but cannot update/delete audit data; the integrity job has a separate read-only
identity.

During an incident, establish a time window and correlation IDs, preserve the collector archive and
other sources before rollover, and compare application operational/security records, protected
audit chains/checkpoints, PostgreSQL, Docker, systemd, SSH/sudo, UFW, Tailscale, backup/restore, and
provider configuration records. Treat missing or contradictory records as a finding. Never paste
raw evidence into a ticket, chat, pull request, or Git commit.

## Known gaps

The application-compromise boundary now has a logically separate security archive, but it is not an
off-host SIEM and does not protect against the trusted Docker/host administrator. The host's
effective journald policy and provider/account settings remain release-only observations. Optional
Tailscale network flow logging is not enabled or assumed. These limitations do not substitute for
the required dated collector delivery, retention, alert review, failure, and escalation checks.
