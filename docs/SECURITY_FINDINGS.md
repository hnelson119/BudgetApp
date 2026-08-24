# Security finding register

This register contains sanitized summaries only. Raw scanner output, attack traces, credentials,
cookies, internal hostnames, and reusable payloads must remain in the ignored `security-reports/`
directory or an encrypted assessment location outside the repository.

## M10-F001 — Stale release base image

- Severity: Critical
- State: Retested
- Detected: 2026-08-24
- Affected baseline: pre-M10 `python:3.12-slim` release image
- Detection: Trivy 0.70.0 image vulnerability and secret scan with a current vulnerability database
- Evidence summary: the Debian runtime contained 3 critical and 50 high operating-system findings;
  installed Python packages reported no high or critical findings, and no embedded secret finding
  was reported.
- Root cause: the immutable Debian base digest preserved packages with newly disclosed findings.
- Remediation: replaced it with the current official `python:3.12-alpine` image pinned to digest
  `sha256:d09d15e60962ca365d1cd544a48773bac9d33f2fb1b00f2aa0deec78ade7dc31`, retained the
  non-root numeric account, read-only filesystem, dropped capabilities, and no-new-privileges
  controls, and added a blocking CI image scan.
- Retest: the rebuilt complete application image reported zero high/critical Alpine or Python
  package findings and no embedded-secret finding. PostgreSQL migrations, the least-privilege
  notification worker, and the web readiness endpoint then passed on the replacement runtime.
- Exceptions or suppressions: none.
- Follow-up: every release candidate must rebuild and pass the blocking image scan because a pinned
  digest does not remain vulnerability-free over time.
