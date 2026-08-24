# Security finding register

This register contains sanitized summaries only. Raw scanner output, attack traces, credentials,
cookies, internal hostnames, and reusable payloads must remain in the ignored `security-reports/`
directory or an encrypted assessment location outside the repository.

## M10-F001 — Stale release base image

- Severity: Critical
- State: Retested
- Detected: 2026-08-24
- Owner: release owner
- Affected baseline: pre-M10 `python:3.12-slim` release image
- Detection: Trivy 0.70.0 image vulnerability and secret scan with a current vulnerability database
- Evidence summary: the Debian runtime contained 3 critical and 50 high operating-system findings;
  installed Python packages reported no high or critical findings, and no embedded secret finding
  was reported.
- Root cause: the immutable Debian base digest preserved packages with newly disclosed findings.
- Remediation: replaced it with the current official `python:3.12-alpine` image pinned to digest
  `sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31`, retained the
  non-root numeric account, read-only filesystem, dropped capabilities, and no-new-privileges
  controls, and added a blocking CI scan using the official Trivy container pinned by digest.
- Retest: the rebuilt complete application image reported zero high/critical Alpine or Python
  package findings and no embedded-secret finding. PostgreSQL migrations, the least-privilege
  notification worker, and the web readiness endpoint then passed on the replacement runtime.
- Exceptions or suppressions: none.
- Follow-up: every release candidate must rebuild and pass the blocking image scan because a pinned
  digest does not remain vulnerability-free over time.

## M10-F002 — Permissive CORS header on public static assets

- Severity: Medium
- State: Retested
- Detected: 2026-08-24
- Owner: release owner
- Affected baseline: the initial M10 synthetic ZAP run
- Detection: ZAP rule 10098 reported `Access-Control-Allow-Origin: *` on the two public,
  fingerprinted application CSS and JavaScript assets. No application page, authenticated response,
  API response, or user data was affected.
- Root cause: WhiteNoise enables cross-origin reads for public static files by default.
- Remediation: set `WHITENOISE_ALLOW_ALL_ORIGINS = False` in the production-derived settings. This
  deployment serves assets from the same origin and does not require cross-origin CDN access.
- Retest: the unauthenticated and both MFA-authenticated scans completed without rule 10098 or any
  other cross-domain alert.
- Exceptions or suppressions: none. The alert was fixed rather than hidden from the report.

## M10-F003 — Plain HTTP in the isolated scanner transport

- Severity: Medium
- State: Accepted
- Detected: 2026-08-24
- Affected environment: the disposable internal-only synthetic pentest network
- Detection: ZAP reported `HTTP Only Site` for the synthetic login page.
- Reason: ZAP and the production-derived app communicate over a private Docker network during this
  one-run test. The pentest settings are guarded by the exact environment, database host, database
  name, and synthetic-data opt-in; they alone disable HTTPS redirect, HSTS, and secure cookies.
  Production settings retain HTTPS redirect, secure `__Host-` cookies, and HSTS.
- Owner: release owner
- Deadline: verify the real VM ingress, certificate, redirect, HSTS, and secure-cookie boundary
  before release-candidate approval and no later than 2026-09-30.
- Acceptance boundary: this exception applies only to the disposable scanner transport. Plain HTTP
  is not accepted for a deployed instance.

## M10-F004 — Nonportable native date-control defaults

- Severity: Low
- State: Retested
- Detected: 2026-08-24
- Owner: release owner
- Affected baseline: initial Chromium, Firefox, and WebKit workflow run
- Detection: every engine retained the manual-expense form instead of accepting the write because
  Django's locale-formatted initial date was not a valid HTML `date` control value.
- Remediation: introduced shared ISO-date and minute-precision time widgets and applied them to all
  audit, budget, debt, goal, and spending native date/time controls.
- Retest: portable widget unit tests and the manual-expense workflow passed in all seven automated
  browser projects.
- Security impact: none observed; validation rejected the incomplete submission and no partial
  ledger write occurred.

## M10-F005 — Font-dependent narrow summary-card overflow

- Severity: Low
- State: Retested
- Detected: 2026-08-24
- Owner: release owner
- Affected baseline: Firefox narrow dashboard and WebKit iPhone Goals view
- Detection: engine-specific font metrics forced two summary cards 7–12 pixels beyond the
  390-pixel viewport.
- Remediation: changed the narrow two-column tracks to shrink-safe `minmax(0, 1fr)` sizing and
  allowed summary text to wrap without expanding its grid item.
- Retest: dashboard, Spending, Debts, and Goals had no horizontal document overflow across every
  desktop, narrow, phone, and iPad project.
- Security impact: none; this was a responsive usability defect.

## 2026-08-24 synthetic browser baseline

- Result: 37 passed, 6 intentionally skipped, and zero failed in 32.5 seconds. The skipped cases
  were duplicate executions of the destructive category-budget deletion proof; its designated
  Chromium desktop execution passed.
- Matrix: Chromium, Firefox, and WebKit desktop; Chromium phone; Firefox narrow; and WebKit iPhone
  and iPad viewports.
- The real password-and-TOTP UI login, HttpOnly/SameSite session cookie, no-store/cache headers,
  CSP, Permissions Policy, X-Frame-Options, local/session storage restrictions, manual expense,
  deletion confirmation, responsive navigation, theme, and no-horizontal-overflow checks passed.
- Reflected query and fragment DOM-XSS probes remained inert in every project. Automated WCAG 2
  A/AA axe checks reported no violation on the dashboard, Debts, or Goals pages in any project.
- The test browser received only a scoped mode-restricted copy of Alex's disposable password and
  TOTP seed. It never mounted the full secret/auth volumes. Screenshots, traces, video, and HTML
  reports were disabled; all synthetic state and Docker resources were removed after execution.
- This is a development baseline, not release-candidate or real-device evidence. Branded browser,
  assistive-technology, real iOS/iPadOS/Android, and remaining manual security passes are pending.

## 2026-08-24 synthetic ZAP baseline

- Unauthenticated: 8 spider URLs, 6 alert types, zero Automation Framework errors/warnings, and no
  High or Critical alert.
- MFA-authenticated Alex: protected audit-page probe returned 200; 640 spider URLs, 3 alert types,
  zero Automation Framework errors/warnings, and no High or Critical alert.
- MFA-authenticated Riley: protected audit-page probe returned 200; 774 spider URLs, 3 alert types,
  zero Automation Framework errors/warnings, and no High or Critical alert.
- Remaining informational observations were ZAP's modern-application classification, recognition of
  session-management responses, authentication-request recognition, user-agent fuzzing, and its
  potential user-controllable HTML-attribute heuristic. The active scan raised no server-side XSS
  finding. The separate browser-driven DOM-XSS baseline subsequently passed in every project.
- All test users, passwords, MFA seeds, sessions, database/media contents, containers, networks, and
  named volumes were generated for the run and removed afterward. Raw reports were reviewed locally,
  summarized here, and deleted after the secret scanner confirmed they contained ephemeral session
  material. They are not release evidence.
- This is a development baseline, not a completed release-candidate penetration-test report. Manual
  authorization, business-logic, audit-tampering, CSV, network, and real-device tests remain.
