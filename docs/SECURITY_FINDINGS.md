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

## M10-F006 — Stale OpenSSL packages in pinned Alpine base

- Severity: High
- State: Retested
- Detected: 2026-08-27
- Owner: release owner
- Affected baseline: commit `b230396` release image in PR #22
- Detection: the blocking Trivy 0.70.0 release-image job used a current vulnerability database and
  identified `CVE-2026-14456` in both `libcrypto3` and `libssl3`.
- Evidence summary: the pinned official Python Alpine image contained OpenSSL `3.5.7-r0`; Alpine's
  official 3.24 repository provided the fixed `3.5.8-r0`. No High/Critical Python-package finding
  or embedded-secret finding was reported.
- Root cause: the immutable base digest had not yet been rebuilt after Alpine published the fixed
  OpenSSL packages. Pinning an image prevents an unexpected base change but cannot keep its
  installed operating-system packages vulnerability-free.
- Remediation: retained the reviewed immutable Python base digest and added a no-cache Alpine
  package upgrade during the release build so current security fixes are applied before the
  unprivileged application user and application layers are created.
- Retest: the complete image rebuilt with OpenSSL `3.5.8-r0`; the same immutable Trivy command and
  a current vulnerability database reported zero High/Critical Alpine or Python-package findings
  and no embedded-secret finding. The application quality gate also passed after the change.
- Exceptions or suppressions: none; the finding is not ignored or severity-downgraded.

## M10-F007 — Anonymous state retained across the password trust boundary

- Severity: Low
- State: Retested
- Detected: 2026-08-28
- Owner: release owner
- Affected baseline: initial disposable `SESS-02` session-fixation probe
- Detection: a controlled server-side marker in a cloned anonymous session survived password
  acceptance and MFA completion even though the session identifier rotated at both transitions.
- Security impact: no reusable identifier fixation or authorization bypass was observed, and the
  application does not expose a client-controlled arbitrary-session-data facility. Retaining
  unrelated anonymous values across a trust transition was nevertheless unnecessary and could
  make a future session-backed feature inherit stale untrusted state.
- Remediation: password acceptance now flushes the anonymous session before writing the three
  pending-MFA fields. Final authentication and recent authentication continue to rotate the new
  identifier.
- Retest: unit coverage proved the old key and marker are absent after password acceptance; the
  disposable HTTP probe then passed pre-authentication, pending-MFA, final-authentication, and
  recent-authentication rotations without preserving the marker.
- Exceptions or suppressions: none.

## M10-F008 — Authentication cookie outlived a normal browser session

- Severity: Medium
- State: Retested
- Detected: 2026-08-28
- Owner: release owner
- Affected baseline: initial disposable `SESS-05` cookie-lifetime probe
- Detection: pending-MFA and authenticated session helpers set explicit time-based expiry values,
  causing a persistent browser cookie despite the production browser-close policy. Server-side
  five-minute pending, one-hour idle, and twelve-hour absolute checks still limited reuse.
- Remediation: both helpers now issue browser-session-only cookies. The existing server-side
  timestamps remain authoritative for pending, idle, and absolute expiry, and database cleanup
  retains its global session age.
- Retest: unit tests, real HTTP cookie-jar checks, and the Chromium/Firefox/WebKit Playwright matrix
  confirmed browser-session-only expiry. The final lifecycle project also proved sign-out removes
  the cookie, back navigation does not reveal the protected audit page, and a fresh context starts
  unauthenticated.
- Exceptions or suppressions: none.

## 2026-08-28 synthetic session-security baseline

- The guarded disposable helper passed `SESS-01` through `SESS-05`: 18 bounded identity/throttle
  checks, 4 trust-transition checks, 7 revocation checks, 8 timeout/concurrency checks, and 6
  cookie/cache checks. It printed no credentials, cookies, identifiers, submitted values, response
  bodies, database contents, or timing samples, and cleanup removed the database and every
  credential/session volume.
- The expanded browser matrix completed with 45 passed, 13 intentionally project-inapplicable
  skips, and zero failed. The destructive Chromium lifecycle proof ran only after all Chromium,
  Firefox, WebKit, phone, narrow, iPhone, and iPad dependencies completed.
- This is supporting development evidence, not a manual scenario result or release-candidate run.
  Password change/forgot-password and individual active-session review/revocation remain missing;
  deployed TLS/`Secure` behavior still requires the private Linux VM target. The adversarial matrix
  therefore remains at zero of three completed targets.

## 2026-08-24 synthetic browser baseline

- Result after the accessibility extension: 44 passed, 13 intentionally skipped, and zero failed
  in 37.4 seconds. The skipped cases were project-inapplicable keyboard/touch checks and duplicate
  executions of the destructive category-budget deletion proof; every designated execution passed.
- Matrix: Chromium, Firefox, and WebKit desktop; Chromium phone; Firefox narrow; and WebKit iPhone
  and iPad viewports.
- The real password-and-TOTP UI login, HttpOnly/SameSite session cookie, no-store/cache headers,
  CSP, Permissions Policy, X-Frame-Options, local/session storage restrictions, manual expense,
  deletion confirmation, responsive navigation, theme, and no-horizontal-overflow checks passed.
- Reflected query and fragment DOM-XSS probes remained inert in every project. Automated WCAG 2
  A/AA axe checks reported no violation on the dashboard, Debts, or Goals pages in any project.
- The Chromium, Firefox, and WebKit desktop projects passed keyboard skip-navigation, visible-focus,
  logical initial focus, and keyboard theme-activation checks. Phone, narrow Firefox, iPhone, and
  iPad layouts exposed primary navigation targets at least 44 CSS pixels high.
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
