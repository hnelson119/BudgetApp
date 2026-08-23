# Contributing

## Workflow

1. Work from a short-lived branch.
2. Keep domain calculations out of views and templates.
3. Add or update tests for every behavior change.
4. Run `scripts/check.ps1` on Windows or `scripts/check.sh` on Linux.
5. Regenerate both requirements lock files and run `python -m pip_audit` when dependencies change.
6. Review generated migrations before committing them.

The GitHub quality workflow runs the same checks, audits the complete development lock, and
validates every Docker Compose profile. Third-party workflow actions must be official, reviewed,
and pinned to an immutable full commit SHA.

When the repository plan supports private branch protection, protect the default branch by
requiring pull requests, the `Python, Django, and security checks` status check, resolution of review
conversations, and branch currency before merge. Disable force pushes and branch deletion. Until
then, treat these requirements as mandatory operating procedure and never force-push or delete
`main`. The two household users do not need repository access unless both will participate in
development or deployment.

Do not commit `.env`, real financial data, database files, CSV imports,
credentials, recovery material, backups, or production logs.

## Definition of done

A change is complete only when its authorization boundary, audit behavior,
financial effect, responsive behavior, and failure path have been considered.
The release-level definition of done remains in `IMPLEMENTATION_PLAN.md`.
