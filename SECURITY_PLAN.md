# Household Budget Application — Security Plan

Status: Approved design baseline
Last updated: 2026-08-24
Companion document: `PRODUCT_SPEC.md`

## 1. Security objective

Protect the confidentiality, integrity, and availability of a two-person household budgeting application hosted on a private Linux VM. Security controls must be practical for a personal deployment, default to least privilege, and preserve a clean path to future public hosting.

The implementation target is OWASP ASVS 5.0 Level 2 where applicable. Any requirement judged not
applicable must be documented with a reason rather than silently skipped. The pinned, requirement-
level review and current gaps are recorded in `docs/ASVS_LEVEL2_MAPPING.md` and
`docs/asvs-5.0.0-level2-evidence.json`.

## 2. Threat model

### 2.1 Protected assets

- Household income, expenses, transaction history, debts, goals, and manual balances
- User passwords, MFA credentials, recovery codes, and active sessions
- Database and backup encryption credentials
- Audit-chain and checkpoint-signing material
- Tailscale device and service identities
- Source code, deployment configuration, and dependency lock files
- Backups, exports, uploaded CSV data, and operational logs

### 2.2 Primary threats

- A lost, stolen, or shared phone, tablet, or computer
- Reused, guessed, phished, or leaked credentials
- A compromised Windows host, Linux VM, browser, or Tailscale device
- Authorization mistakes that expose another household's records if multi-household support is added
- Cross-site scripting, CSRF, SQL/command injection, insecure direct-object access, and session theft
- Malicious, malformed, oversized, or formula-bearing CSV content
- Vulnerable or compromised packages and container images
- Ransomware, disk failure, corrupted updates, and accidental deletion
- Unauthorized modification or deletion of audit history
- Incorrect firewall, reverse-proxy, or Tailscale policy changes
- Future accidental exposure of a private-only service to the public internet

### 2.3 Trust boundaries

1. User device and browser
2. Tailscale private network
3. HTTPS reverse proxy
4. Web application container
5. PostgreSQL container network
6. Linux VM administration boundary
7. Windows Hyper-V host
8. Backup and audit-checkpoint destinations

Data crossing any boundary must be authenticated, authorized, validated, and protected in transit where applicable.

### 2.4 Explicit limitations

An administrator controlling the Windows host, Linux VM, database superuser, runtime secrets, and every backup destination can ultimately defeat local controls. The design reduces this risk through separation of roles, off-VM checkpoints, versioned backups, encryption, and visible integrity verification. It promises tamper resistance and tamper evidence, not absolute immutability.

## 3. Identity and account recovery

### 3.1 Separate identities

- Each household member has an individual application account.
- Shared usernames and shared application passwords are prohibited.
- Each account has an independent Tailscale identity and approved devices.
- Both members have equal financial permissions, but actions remain individually attributable.

### 3.2 Application authentication

- MFA is required after initial enrollment.
- Prefer passkeys/WebAuthn; support TOTP as the practical fallback.
- SMS and email codes are not primary MFA methods.
- Passwords use the framework's current secure password hasher and are never reversibly encrypted.
- Passwords may be long passphrases and are checked against reasonable strength rules without forced periodic rotation.
- Password changes require recent password-plus-MFA verification and the current password, rotate
  the surviving session, revoke every other session, and never retain submitted password values.
- Authentication responses do not reveal whether a username exists.
- Failed authentication is rate-limited and audited without recording attempted passwords.

### 3.3 Recovery

- Generate single-use recovery codes during MFA enrollment.
- Store only cryptographic hashes of recovery codes in the database.
- Show recovery codes once and require the user to confirm they saved them.
- Security questions are prohibited.
- Forgotten-password recovery requires a current TOTP or one unused recovery code; it does not use
  email links, security questions, or a weaker fallback factor.
- Recovery returns the same submitted response for known, unknown, inactive, and invalid attempts,
  applies keyed identifier/network throttling, never creates an authenticated session, and logs no
  submitted identity, password, authenticator value, or recovery code.
- Successful recovery consumes the factor, changes the password atomically with protected audit
  events, revokes every prior session, and requires the new password plus fresh MFA at sign-in.
- A local emergency-recovery command may reset an account only with VM administrative access.
- Emergency recovery revokes all active sessions, invalidates old recovery codes, requires new MFA enrollment, and creates a protected audit event.

### 3.4 Sensitive actions

Require recent password/MFA verification before:

- Changing a password, passkey, TOTP secret, or recovery codes
- Managing household members
- Exporting all household data or audit history
- Initiating or restoring backups from the UI, if later supported
- Changing security, audit, retention, or integration settings
- Creating future bank synchronization credentials

## 4. Session and browser security

- Use opaque server-side sessions generated by the framework.
- Store the session identifier only in a cookie using `Secure`, `HttpOnly`, `SameSite=Strict`, and `Path=/`.
- Use a `__Host-` cookie prefix when compatible with the deployment hostname.
- Never store session IDs, access tokens, refresh tokens, or financial datasets in `localStorage` or `sessionStorage`.
- Rotate the session identifier after authentication and privilege-sensitive changes.
- Default session limits: 60-minute inactivity timeout and 12-hour absolute lifetime.
- Show only the current user's active server-side sessions through keyed, non-reversible action
  references; do not expose raw session identifiers or retain detailed device fingerprints.
- Require recent password-plus-MFA verification before individual or all-session revocation.
- Provide “Log out all devices” and revoke other sessions after password changes and every session
  after password or MFA recovery.
- Provide a guarded trusted-console operation for an administrator to revoke one arbitrary
  account's sessions or every account's sessions without changing credentials. Rotate the
  server-side session version, remove stored authenticated and pending-MFA sessions, and record the
  reason in the protected household audit stream.
- Send `Cache-Control: no-store` on authenticated financial pages and exports.
- Clear relevant cookies and browser storage on logout.
- Apply CSRF protection to every state-changing request.
- Reauthenticate sensitive actions even when a valid session exists.

## 5. Tailscale and network boundary

### 5.1 Tailnet policy

- Require MFA on the identity provider accounts used for Tailscale.
- Enable device approval.
- Tag the VM with a dedicated identity such as `tag:budget-server`.
- Permit approved household users/devices to reach only the budget application's HTTPS port.
- Do not provide general access from household mobile devices to the Windows host, database, Docker API, or unrelated LAN devices.
- Do not configure the budget VM as an exit node or subnet router.
- Retain device-key expiry and review approved devices periodically.
- Revoke missing, replaced, or unused devices immediately.
- Avoid reusable Tailscale auth keys; if automation requires one, scope it narrowly, expire it, and store it outside source control.

### 5.2 Service exposure

- Do not forward router ports to the VM.
- Bind the reverse proxy to the Tailscale/private interface only.
- Expose the web app through HTTPS only.
- Choose a neutral internal hostname because certificate names may appear in public certificate-transparency records.
- PostgreSQL has no host or public listening port and is reachable only on the private container network.
- SSH is reachable only through Tailscale, uses keys, and disallows password and direct root login.

### 5.3 Host firewalls

- Keep Windows Defender Firewall enabled on the Hyper-V host.
- Configure the Linux firewall default inbound policy to deny.
- Permit only required Tailscale, HTTPS, and restricted administration traffic.
- Tailscale supplements rather than replaces host firewalling.

## 6. Application security controls

### 6.1 Authorization

- Enforce authentication and household membership server-side for every request and object lookup.
- Scope every financial query and mutation by household ID.
- Never treat a hidden button, URL secrecy, sequential ID, or UUID as authorization.
- Centralize permission checks rather than duplicating ad hoc checks in views.
- Deny by default and audit authorization failures.
- Add automated tests attempting cross-user, cross-household, direct-object, and role-bypass access.

### 6.2 Input and output handling

- Validate data type, range, length, format, and business rules on the server.
- Use Django ORM parameterization; raw SQL requires review and bound parameters.
- Do not invoke operating-system shells with user-controlled values.
- Escape untrusted text in HTML and prohibit user-supplied HTML in the initial release.
- Apply a restrictive Content Security Policy.
- Use security headers including HSTS, `frame-ancestors`, `X-Content-Type-Options`, and a restrictive referrer policy.
- Reject unexpected HTTP methods and content types.
- Place reasonable request-body, pagination, and rate limits on expensive endpoints.

### 6.3 Financial integrity

- Use exact decimal types for currency and deterministic rounding rules.
- Use database transactions for multi-record financial operations.
- Add idempotency protection to imports and operations vulnerable to double submission.
- Financial writes and their audit events either both commit or both fail.
- Validate recurrence changes and show their future-period impact before commit.

Implementation note: debt accounts can be changed only through household-authorized transactional
services that append protected audit events. Effective-dated debt terms and lender statements are
append-only, direct ORM update/delete paths are rejected, and PostgreSQL runtime-role triggers deny
update, delete, or truncate. A statement correction appends a linked replacement and retains the
original record. Operational logs receive request and failure context, not statement values, account
notes, or projection payloads.

Split-mortgage plans use the same defense in depth. The stable plan, effective-dated revisions,
component allocations, and two installment rules can be created only through a household-scoped
transactional service. PostgreSQL triggers reject update, delete, and truncate for every mortgage
history table. Preview fingerprints prevent a changed or stale two-schedule configuration from
being confirmed, and one-off extra principal delegates to the protected occurrence-override path so
the recurring source revisions remain unchanged. Mortgage component values and occurrence amounts
remain out of operational logs; protected audit events retain the authorized financial change and
reason.

## 7. CSV import and export security

### 7.1 Import

- Accept `.csv` only in the initial release.
- Validate content rather than trusting the extension or browser-provided MIME type.
- Default maximum: 5 MiB and 10,000 data rows per import; make limits configurable downward.
- Stream or bound parsing so a file cannot exhaust memory.
- Reject invalid encodings, malformed quoting, excessive columns, and excessively long cells.
- Never evaluate formulas, macros, links, or embedded commands.
- Do not persist the uploaded file; if a future importer requires temporary files, keep them outside
  the web root with generated filenames and restrictive permissions.
- Delete staged raw cells after successful import, explicit abandonment, or a maximum 24-hour
  failed/incomplete-import retention window.
- Commit no transactions until the user reviews mapping, preview, duplicate results, and category gaps.
- Use an idempotent import-batch identifier and normalized transaction fingerprints.

Implementation note: CSV uploads are parsed from a bounded Django upload stream and closed without
being copied into application media storage. Only bounded cells are staged; commit or abandonment
scrubs those raw cells. An hourly least-privilege job locks and rechecks uploaded/previewed batches
older than 24 hours, scrubs them, and appends a protected system audit event without recording row
contents. Household scoping is enforced again in the domain service, and the final ledger writes
plus batch audit event share one database transaction.

### 7.2 Export

- Treat all text fields as untrusted when generating CSV.
- Neutralize untrusted text cells that spreadsheet software could interpret as formulas, including values beginning with `=`, `+`, `-`, or `@` after leading whitespace.
- Serialize validated Decimal amount columns as numeric values; do not convert legitimate negative financial amounts into text merely because they begin with `-`.
- Send exports as attachments with `Cache-Control: no-store`.
- Prefer streaming generation; securely remove any temporary export file.
- Require recent reauthentication for full household and audit exports.
- Audit who exported what scope and when, without storing the exported file in the audit log.

Implementation note: transaction CSV export requires recent password-plus-MFA verification and
successfully verifies the household audit chain before generation. It reuses the server-enforced
transaction filters, streams directly from the household-scoped query without a temporary file,
neutralizes every untrusted text field, and leaves Decimal amount cells numeric. The attachment is
marked `no-store`; its protected audit event contains only the actor, export identifier, scope,
filter metadata, row count, and time—not the file, search text, or transaction contents.

## 8. Data minimization and encryption

- Do not store banking usernames, passwords, PINs, or full card numbers.
- Manual accounts use a user-selected label and optional last four digits only.
- Do not retain complete raw bank CSV files after import processing.
- Keep operational logs free of balances, transaction payloads, tokens, passwords, and recovery codes unless specifically required by the protected financial audit record.
- Protect the Windows volume containing the VM with BitLocker and recovery-key escrow appropriate for the household.
- Encrypt backups before they leave the VM.
- Use HTTPS between browsers and the private application even though Tailscale traffic is encrypted.
- Document encryption-key generation, storage, backup, rotation, compromise response, and retirement.
- Keep data-encryption and audit-signing keys separate from the database and source repository.

## 9. Secrets management

- Never commit secrets, private keys, recovery material, `.env` files, database dumps, or real household data to source control.
- Generate secrets using cryptographically secure tools; do not invent human-readable secrets.
- Store runtime secrets in an OS-protected deployment location with permissions limited to the required service account.
- Do not bake secrets into container images.
- Use separate credentials for application runtime, migrations, backups, and audit checkpointing.
- Scope every credential to the minimum operations required.
- Support rotation without rebuilding the database or losing access to older encrypted backups.
- Keep the audit-checkpoint signing key outside the Linux VM when practical.
- Run secret scanning before commits and in the release workflow.

## 10. Host and container hardening

### Windows host

- Keep Windows, Hyper-V, Tailscale, firmware, and endpoint protection current.
- Enable BitLocker, Secure Boot, and automatic screen locking where supported.
- Do not expose RDP to the public internet.
- Use a non-administrator daily account where practical.

### Linux VM

- Use a supported minimal server distribution.
- Enable automatic security updates or a documented rapid patch routine.
- Remove or disable unused services and packages.
- Restrict administrative users and require sudo rather than routine root sessions.
- Synchronize time reliably because schedules and audit chains depend on timestamps.

### Containers

- Run application processes as non-root users.
- Use rootless Docker when it is compatible with the deployment; otherwise apply user namespaces and least privilege.
- Never use privileged containers.
- Never mount the Docker socket into the web application.
- Drop unnecessary Linux capabilities and use `no-new-privileges`.
- Use read-only filesystems and explicit writable volumes where practical.
- Apply memory, process, and storage limits.
- Pin base images and dependencies; use minimal maintained images.

## 11. Software supply chain and secure development

- Commit dependency lock files and verify reproducible builds.
- Scan Python, JavaScript, and container dependencies for known vulnerabilities.
- Pin production container bases by immutable version or digest.
- Treat dependency updates as reviewed changes with automated tests.
- Apply critical/high security fixes promptly; target seven days or less when exploitation risk is material.
- Review routine security and OS updates at least monthly.
- Run static analysis, secret scanning, and security-focused test suites before release.
- Protect the main branch from unreviewed deployment changes once development begins.
- Keep production-like secrets and real household data out of development and test fixtures.

## 12. Audit, monitoring, and alerting

The protected financial audit design remains defined in `PRODUCT_SPEC.md`.

Additionally:

- Keep operational/security logs separate from the financial audit stream.
- Record authentication failures, MFA/recovery changes, authorization failures, data exports, backup/restore operations, deployment changes, and integrity-check results.
- Do not log passwords, TOTP seeds, recovery codes, session cookies, database credentials, or raw CSV files.
- Rotate and retain operational logs for a documented period.
- Show in-app security notifications for repeated failed logins, account recovery, new sessions, audit-integrity failure, backup failure, and overdue security updates where detectable.
- Verification failure must never be hidden by a later successful check; both results remain recorded.

## 13. Backup and recovery

### 13.1 Recovery objectives

- Initial recovery-point objective: no more than 24 hours of committed data loss.
- Initial recovery-time objective: restore service within one day when replacement hardware is available.

### 13.2 Backup layers

- Daily encrypted PostgreSQL backup copied outside the VM.
- Versioned backup history so synchronized corruption or deletion can be rolled back.
- Periodic encrypted copy on a disconnected drive or independent destination.
- Separate daily audit-chain checkpoint outside the VM.
- Separate protected copy of required decryption keys and recovery instructions.
- Backups must include database schema version and application release identifier.

### 13.3 Verification

- Automatically verify backup completion and basic archive integrity.
- Perform a test restore at least quarterly and before risky migrations.
- Verify the restored audit chain against an external checkpoint.
- Document the full restore process and expected order of secrets, database, application, and verification steps.

## 14. Incident response

Maintain a short runbook for:

1. Revoking a lost or compromised Tailscale device
2. Disabling an application account and administratively terminating one or all accounts' sessions
3. Isolating the Linux VM from the tailnet
4. Preserving logs and audit checkpoints
5. Rotating application, database, Tailscale, backup, and audit credentials
6. Checking dependency and host compromise indicators
7. Selecting and restoring a known-good backup
8. Verifying the audit chain after restore
9. Re-enrolling users and devices
10. Recording the incident and corrective actions

The runbook and recovery credentials must be available without relying on the budget application being online.

## 15. Future public-hosting gate

Moving to a public domain requires a deliberate security review. Do not expose the current private deployment directly by opening router ports.

Before public release:

- Confirm MFA and recovery flows are enforced.
- Rotate all deployment secrets and keys.
- Run the ASVS checklist and an external vulnerability scan.
- Verify rate limits, secure headers, TLS, monitoring, backups, and incident response.
- Review reverse-proxy trust settings and forwarded headers.
- Ensure PostgreSQL and administration interfaces remain private.
- Add reliable security-notification delivery.
- Review privacy, retention, and account-removal behavior.
- Perform authorization and upload/export penetration tests.

## 16. Future bank-synchronization gate

- Never collect or store bank usernames, passwords, or PINs.
- Use a reputable provider's authorization flow and least-privilege scopes.
- Encrypt provider tokens separately from ordinary financial records.
- Verify webhook signatures and prevent replay.
- Provide visible connection revocation and token deletion.
- Audit connection, refresh, import, failure, and revocation events without logging tokens.
- Complete a separate privacy and threat-model review before enabling the feature.

## 17. Required security tests

Before the initial release, verify:

1. An unapproved device cannot reach the application.
2. Approved users can reach only the budget service allowed by the tailnet policy.
3. HTTP does not expose an authenticated application endpoint.
4. Session cookies use the required flags and are absent from browser storage.
5. CSRF attempts fail for every state-changing operation.
6. A user cannot access an object outside their authorized household by changing an ID.
7. Login rate limiting and account recovery do not disclose usernames or secrets.
8. Password/MFA recovery revokes existing sessions.
9. Oversized, malformed, and non-CSV uploads are rejected safely.
10. Import content is never executed and duplicate batches are idempotent.
11. CSV exports neutralize spreadsheet-formula payloads.
12. Application and database containers do not run with unnecessary privileges.
13. PostgreSQL cannot be reached from a household client device.
14. Source and container scans contain no known unaccepted critical vulnerabilities or secrets.
15. Audit records cannot be modified with runtime credentials.
16. Audit mutation or removal causes verification to fail visibly.
17. A failed audit write rolls back its associated financial write.
18. An encrypted backup restores successfully without the original VM.
19. The restored audit chain matches an external checkpoint.
20. Lost-device and credential-rotation runbooks can be completed from the documented instructions.
21. Authenticated functionality passes security smoke tests in Chromium, Firefox, and WebKit without weakening cookie, CSRF, CSP, or cache controls for browser compatibility.
22. Current Firefox mobile smoke tests pass on the supported mobile platforms without storing sensitive data in browser storage.
23. The release-candidate penetration test produces no unresolved critical or high-severity finding.
24. Every remediated penetration-test finding is retested, and the final report contains no real household data or reusable credential.

## 18. Penetration testing and adversarial validation

Penetration testing is a release activity, not a substitute for code review,
automated tests, dependency scanning, or threat modeling.

### 18.1 Timing and environment

- Run a passive authenticated scan during release-candidate testing.
- Run the complete active assessment before the first real household-data release.
- Repeat it annually and after material changes to authentication, authorization,
  private ingress, file import, audit protection, or future bank integrations.
- Use an isolated production-like environment containing synthetic accounts,
  transactions, debts, goals, CSV files, passkeys, and recovery codes.
- Snapshot or back up the test environment first and confirm that it can be
  restored. Never run destructive or high-volume testing against production.
- Scope the exact hostnames, accounts, test window, request-rate ceiling, and
  prohibited third-party targets before a scan begins.

### 18.2 Coverage

- Test from an unapproved LAN device, an approved tailnet device, and an
  authenticated browser session for each household user.
- Verify that the application and PostgreSQL are unreachable outside their
  intended network boundaries.
- Cover identity enumeration, brute-force controls, password/passkey/TOTP
  recovery, session fixation, session replay, logout, and logout-all-devices.
- Test CSRF, XSS, SQL/command injection, path traversal, header spoofing, host
  validation, cache leakage, clickjacking, unsafe redirects, and error leakage.
- Attempt direct-object, cross-household, mass-assignment, privilege, and
  administrative endpoint bypasses.
- Exercise CSV uploads, duplicate imports, spreadsheet formulas, oversized and
  malformed inputs, and temporary-file cleanup.
- Test financial business logic, including card-payment double counting,
  negative or excessive allocations, period-boundary moves, closed-period
  corrections, mortgage splits, and concurrent submissions.
- Attempt audit mutation, deletion, chain splicing, checkpoint substitution,
  and financial writes when audit append fails.
- Inspect browser storage, container configuration, image layers, logs,
  diagnostics, backups, and process metadata for credential or data leakage.

### 18.3 Tools and manual review

- Use OWASP ZAP's Automation Framework for repeatable passive and active scans,
  including authenticated application paths.
- Use narrowly scoped host and port discovery to prove that only intended
  Tailscale and loopback services are reachable.
- Retain the ASVS requirement mapping and OWASP Web Security Testing Guide test
  identifiers used for manual testing.
- Use `docs/ADVERSARIAL_TESTING.md` and its machine-validated matrix and sanitized run records for
  the authorization, session, CSV, financial-logic, audit-integrity, and network-boundary pass.
- Automated scanner results require manual validation. Manual business-logic
  and authorization testing remains mandatory because scanners cannot prove
  household isolation or financial correctness.

### 18.4 Findings and exit criteria

- Record affected release, environment, test account, severity, evidence,
  reproduction outline, remediation, owner, and retest result.
- Store reports as sensitive security artifacts without session tokens,
  passwords, real financial data, or reusable exploit credentials.
- Fix and retest every critical or high-severity finding before release.
- Document and time-bound any accepted medium-severity finding; low-severity
  findings enter the normal backlog.
- A public deployment or bank-data integration requires a fresh threat model
  and should receive an independent human penetration test rather than relying
  only on the project's own assessment.

## 19. Security decisions that do not require enterprise infrastructure

The initial deployment does not require Kubernetes, a public WAF, enterprise SIEM, HSM, dedicated firewall appliance, cloud key vault, or 24/7 security operations. These may be reconsidered if the service becomes public, adds more households, or connects to financial institutions.

## 20. References

- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Authentication: https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html
- OWASP MFA: https://cheatsheetseries.owasp.org/cheatsheets/Multifactor_Authentication_Cheat_Sheet.html
- OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP File Upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP CSV Injection Testing: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/21-Testing_for_CSV_Injection
- OWASP Cryptographic Storage: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- OWASP Secrets Management: https://cheatsheetseries.owasp.org/cheatsheets/Secrets_Management_Cheat_Sheet.html
- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/latest/
- OWASP ZAP Automation Framework: https://www.zaproxy.org/docs/automate/automation-framework/
- Tailscale Security Best Practices: https://tailscale.com/docs/reference/best-practices/security
- Tailscale Device Approval: https://tailscale.com/docs/features/access-control/device-management/device-approval
- Docker Rootless Mode: https://docs.docker.com/engine/security/rootless/
- CISA Ransomware Guide: https://www.cisa.gov/sites/default/files/2023-01/CISA_MS-ISAC_Ransomware%20Guide_S508C.pdf
