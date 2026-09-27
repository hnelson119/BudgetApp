# Anti-automation policy

BudgetApp applies layered anti-automation controls to every named application route. The
machine-readable source of truth is `docs/anti-automation-policy.json`; its checker discovers all
named routes from the nine application URL modules and fails if a route is missing, duplicated, or
silently moved between risk families.

Routine authenticated state changes share a database-backed account budget of 120 requests per five
minutes. The counter is checked before view execution for `POST`, `PUT`, `PATCH`, and `DELETE`, so
invalid submissions and unsuccessful state transitions also consume capacity. Exhaustion returns
`429`, a bounded `Retry-After`, private no-store headers, and a minimized security event. Fixed
windows do not extend when blocked requests arrive, which prevents an attacker from indefinitely
locking out a household member by continuing to send requests.

Logout and session-revocation routes are deliberately exempt from the general mutation budget so a
member can always terminate suspected compromised access. They remain authenticated and
account-scoped, operate over at most five concurrent sessions, and terminate state instead of
creating records.

Higher-risk operations use tighter shared budgets:

| Operation family | Account budget | Placement |
| --- | ---: | --- |
| Transaction and audit CSV exports | 5 per 15 minutes | After recent authentication, before integrity scans, counts, audit writes, or streaming |
| CSV upload intake | 10 per 15 minutes | Before form and file parsing |
| Debt projections and notification refresh | 20 per 15 minutes | Before projection or household-wide recalculation |
| Authentication, MFA, recovery, and reauthentication failures | 5 per 15 minutes, followed by a 15-minute block | Before another credential or recovery attempt can succeed |

Each request also retains its independent business, authorization, file-size, row-count, result,
projection-horizon, process, memory, connection, and timeout limits. Read-only histories use fixed
pages or result caps. Operational health endpoints remain behind the documented private ingress
and deployment ceilings. These controls cover data exfiltration, garbage-data creation, quota and
storage exhaustion, repeated expensive calculations, and request-level denial of service without
depending on a single global counter.

The limits are per account because the application has two trusted household users and must not
allow one user or a forged network identity to lock out the other. Pre-authentication identity
failures also use a keyed network pseudonym. Private ingress, nginx connection limits, two bounded
Gunicorn workers, container quotas, and request timeouts provide the independent distributed-load
boundary.

Repository tests establish implementation, not release verification. Representative release-host
load and false-positive observation remain release work.
