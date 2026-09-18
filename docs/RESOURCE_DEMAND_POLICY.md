# Resource-demand and response-time policy

Status: implemented documentation boundary; release load verification pending
Last reviewed: 2026-09-13
Next review due: 2026-12-12

## Availability objective

BudgetApp is a private, two-user household service. Interactive requests must remain small enough
to return their first response within the explicit 30-second Gunicorn worker budget. Nginx allows
65 seconds of upstream silence so it does not abandon a response before Gunicorn does, and limits
slow request headers and bodies to 15 seconds and stalled response delivery to 30 seconds. Streaming
downloads must yield incrementally rather than construct the complete file in memory.

Resource-intensive operator work never runs through an HTTP request. Backup, restore, migration,
key rotation, audit checkpoint, notification generation, and stale-import cleanup are separate
one-shot maintenance services. The operator must schedule only one maintenance job at a time and
must not overlap it with restore, upgrade, or heavy interactive use.

## Reviewed resource-demanding functionality

| Functionality | Execution and demand | Availability and timeout strategy |
| --- | --- | --- |
| CSV upload, preview, and commit | Synchronous HTTP parsing and database writes | Input is capped at 5 MiB, 10,000 rows, 50 columns, and 1,000 characters per cell. Reads use 64 KiB chunks, previews show 100 rows, staged data expires, and a transaction makes retry behavior deterministic. Before release, load evidence must show the configured maximum finishes inside the worker budget; otherwise lower the row limit or move commit processing to a queued job. |
| Debt payoff and schedule projections | Synchronous CPU and database work | Debt comparisons accept at most 100 debts and 1,200 months. Recurrence generation is capped at 10,000 occurrences and 25 years, while persisted schedule synchronization is capped at five years. Increasing any horizon requires repeatable timing and memory evidence. |
| History, preview, and notification views | Synchronous database reads and template rendering | Transaction and audit history use 50-row pages. Import history and preview expose at most 100 rows, and notification history exposes at most 200. New collection views must add a fixed page or result limit. |
| Transaction and audit CSV exports | Streaming HTTP database reads | Rows are read with 200-row database iterators and encoded one at a time, so the application does not build a complete response or retained export file. Filters should be used for large histories. Long-running exports still occupy one of two web workers and remain a release-load-test risk. |
| Authentication and password checks | Synchronous cryptography and database work | Password checks use the bounded local corpus, MFA work has fixed input and drift windows, and keyed identifier/network throttles block repeated failures after five attempts in 15 minutes. No password-derived network request is made. |
| Notifications, cleanup, and security logging | Interactive refresh plus scheduled one-shot work | Notification lists are capped at 200. Routine generation and stale-import cleanup have dedicated maintenance commands. Security logs use bounded 32 KiB local datagrams and a separate 32-PID, network-isolated collector so archive trouble does not block request completion. |
| Backup, restore, migration, rotation, and audit integrity | Operator-triggered database, storage, and cryptographic work | These tasks are isolated Compose maintenance or recovery profiles, never request handlers. They use separate service identities, bounded process trees and temporary filesystems, explicit rehearsals, and operator-controlled serialization. |

## Concurrency and infrastructure envelope

Production exposes two synchronous Gunicorn workers behind one Nginx worker with 256 connection
slots. The web process is limited to 128 PIDs, ingress to 64, and the isolated security-log service
to 32. Request buffering and the 6 MiB ingress body ceiling reject oversized bodies before Django's
5 MiB application limit is exceeded. These limits contain process and request amplification, but
the Compose file does not yet set CPU or memory quotas; the release host must apply and validate
those limits before `v5.0.0-15.2.2` can be considered complete.

## Failure, retry, and response rules

- A worker that remains silent for 30 seconds is terminated and replaced. Nginx's 65-second
  upstream-read window provides headroom for that failure rather than manufacturing an earlier 504.
- No interactive operation may catch a timeout and continue unobserved in the request process.
  Idempotency tokens, row locks, and database transactions protect retried write workflows.
- Streaming responses must emit bounded chunks. If an export cannot continue, it fails as an
  incomplete download; the user can retry with a narrower filter.
- Repeated authentication failures are throttled by pseudonymous account and network keys. Rate
  limiting must not reveal whether an account exists.
- Maintenance failures remain visible in service exit status and structured operational alerts.
  They are retried by the operator only after the competing job or capacity problem is resolved.

## Change and release control

The machine-readable inventory in `docs/resource-demand-policy.json` and its fail-closed checker pin
the current limits, timeout ordering, concurrency envelope, and source evidence. A new expensive
endpoint, changed limit, removed streaming boundary, timeout inversion, or stale review fails the
normal quality gates.

For every release candidate, exercise maximum-size CSV parsing and commit, the 100-debt/1,200-month
projection boundary, large filtered exports, notification refresh, and simultaneous ordinary page
loads on representative VM resources. Record wall time, peak memory, database duration, response
status, and whether either web worker restarted. Keep `v5.0.0-15.2.2` partial until this evidence
exists and CPU/memory quotas are enforced. If a synchronous operation approaches 20 seconds under
that load, reduce its limit or move it to a bounded per-user and application-wide queue before
release.
