# Database migration policy

- Generate migrations with the Django version pinned by the project.
- Review migration operations before applying them to any shared environment.
- Never edit or delete a migration that has reached a shared environment.
- Prefer additive, backwards-compatible schema changes before destructive cleanup.
- Back up PostgreSQL and verify the latest audit checkpoint before a risky migration.
- Test forward migration and restore/rollback procedures on a copy without real data.
- Keep data migrations deterministic, bounded, restart-safe, and free of network calls.
- Run `makemigrations --check --dry-run` in the quality gate to detect model drift.
- Application and audit-schema privilege changes require explicit deployment review.
- Append-only financial-history migrations must add a runtime-role mutation guard and a
  rollback-only PostgreSQL rehearsal; M5 applies this to occurrence reconciliation records.
- Run `db-bootstrap` before migrations so the non-login `budget_audit_owner` and fixed capability
  roles exist. Audit migrations move their tables into `budget_audit`, transfer ownership, and
  must explicitly reapply the runtime `SELECT`/append-function boundary after every schema change.
