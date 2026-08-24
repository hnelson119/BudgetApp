# Release hardening and evidence

Status: Milestone 10 baseline in progress  
Last updated: 2026-08-24

## Purpose

Milestone 10 turns the existing security controls into a repeatable release decision. The
machine-readable inventory in `docs/release-evidence.json` tracks all 17 OWASP ASVS 5.0 chapters,
the 24 required security tests in `SECURITY_PLAN.md`, and the 12 release gates in
`IMPLEMENTATION_PLAN.md`. A control is not a release pass merely because code or a unit test exists.

The ASVS review is pinned to OWASP ASVS 5.0.0 Level 2. Chapters V9, V10, and V17 are currently not
applicable because the private release has no self-contained authentication tokens, OAuth/OIDC, or
WebRTC. Requirement-level applicability and evidence will be completed before the release candidate
is approved.

## Evidence states

- `not_started`: no release verification has been performed.
- `partial`: some relevant controls or tests exist, but the requirement is incomplete.
- `implemented`: a repeatable control and test exist; release-candidate execution is still pending.
- `verified`: a dated release-candidate run passed and a sanitized evidence reference is recorded.
- `not_applicable`: the product does not contain the relevant feature and records why.

Only `verified` and justified `not_applicable` items satisfy a final release review. The inventory
validator rejects missing identifiers, unknown states, duplicate entries, unreasoned exclusions,
and undated verified claims.

## Automated baseline

Run the normal local gate:

```powershell
.\scripts\check.ps1
```

This includes Django checks, migration drift, Ruff, mypy, secret scanning, evidence-ledger
validation, Bandit, the complete test suite, line coverage, and branch coverage. Dependency audit
remains an explicit network-backed command:

```powershell
.\.venv\Scripts\python.exe -m pip_audit --requirement requirements-dev.lock --cache-dir .pip-audit-cache --no-deps --disable-pip --strict
```

GitHub Actions independently builds the production image without runtime secrets and uses the
official Trivy action pinned to an immutable commit. Any known high or critical operating-system or
Python-package vulnerability fails the image job. The existing dependency, source, configuration,
and secret checks remain separate so one scanner cannot silently replace another.

The initial image scan identified and remediated `M10-F001`; its sanitized finding and clean retest
are recorded in `docs/SECURITY_FINDINGS.md`. This result is baseline evidence, not a future release
pass: every candidate must rebuild and rescan the pinned image against the then-current database.

## Evidence handling

Do not commit raw ZAP sessions, attack payloads, cookies, TOTP material, passwords, internal
hostnames, database dumps, or detailed scanner reports. Local tool output belongs under the ignored
`security-reports/` directory or in an encrypted assessment location outside the repository. Commit
only sanitized summaries, finding identifiers, affected release, severity, remediation, and retest
status.

Every finding uses these states: `open`, `accepted`, `remediated`, or `retested`. Critical and high
findings cannot be accepted for the initial release. Medium acceptance requires a reason, owner, and
deadline. A retest must reproduce the original request boundary and confirm the fix without using
real household data.

## Execution order

1. Finish the ASVS 5.0.0 requirement-level applicability and evidence mapping.
2. Complete the automated Chromium, Firefox, and WebKit accessibility/responsive suites.
3. Build the isolated synthetic PostgreSQL penetration-test profile.
4. Run unauthenticated ZAP passive/active automation, then authenticated automation for both users.
5. Complete manual authorization, session, CSV, financial-logic, audit, and network tests.
6. Remediate and retest findings.
7. Run restore/checkpoint, lost-device, credential-rotation, upgrade, and rollback rehearsals.
8. Mark a gate verified only after retaining dated, sanitized evidence.

## Current baseline gaps

- Private Tailscale ingress and firewall isolation require the Linux VM.
- ZAP automation and the disposable synthetic environment have not yet been added.
- Firefox/WebKit automation and real-device mobile passes have not yet run.
- The release-candidate restore, audit-checkpoint comparison, lost-device, rotation, upgrade, and
  rollback rehearsals remain pending.
- No penetration-test result is claimed yet.
