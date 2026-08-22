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
