# Backup and restore runbook

The application uses PostgreSQL logical backups streamed directly into an encrypted Restic
repository. The web container has neither database-backup credentials nor repository keys.
Never mount the Docker socket or the encrypted repository into the web container.

## Recovery objectives

- Recovery point: no more than 24 hours of committed data under the daily schedule.
- Recovery time: service restored within one day when replacement hardware is available.
- Retention: 7 daily, 4 weekly, and 12 monthly snapshots by default.

## Prepare the repository

`BUDGET_BACKUP_REPOSITORY` must point to an existing mount outside the VM. Compose uses
`create_host_path: false`, so a missing external mount fails safely instead of silently writing
backups to the VM disk. On the Linux host, grant the backup container's `postgres` user (UID 70)
write access to that directory without granting access to the application user.

Create `restic_repository_password` alongside the other deployment secrets. Keep an independent
protected copy of this password and the runbook; losing it makes the encrypted backups unusable.

## Create and inspect a backup

Run the following from the deployment directory:

```bash
docker compose --profile maintenance build backup
docker compose --profile maintenance run --rm backup
```

The command initializes an empty repository when necessary, streams `pg_dump` into Restic, checks
repository integrity, and applies retention. It logs event names and outcomes but never secret
values or financial records.

The supplied systemd units assume the deployment checkout is `/opt/household-budget`, Docker is
`/usr/bin/docker`, and non-secret Compose configuration is stored in
`/etc/household-budget/household-budget.env`. Review those paths on the VM, then install and enable
the timer:

```bash
sudo install -m 0644 deploy/systemd/household-budget-backup.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/household-budget-backup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now household-budget-backup.timer
systemctl list-timers household-budget-backup.timer
```

The timer runs daily around 03:15 with a randomized delay and catches up after downtime. Alert on a
failed unit and review results without exposing secrets:

```bash
systemctl status household-budget-backup.service
journalctl -u household-budget-backup.service --since yesterday
```

For manual repository inspection, use a short-lived container rather than installing Restic on
the application host. Do not expose repository credentials to the web service.

```bash
docker compose --profile maintenance run --rm backup restic snapshots --latest 5
```

## Quarterly restore verification

Choose a new target name using the required `<production_db>_restore_<label>` pattern. The verifier
refuses the live database name and refuses to overwrite any existing database.

```bash
RESTORE_SNAPSHOT_ID=latest \
RESTORE_TARGET_DB=household_budget_restore_2026q3 \
docker compose --profile recovery run --rm restore-verify
```

The verifier mounts the repository read-only, streams the dump into a newly created database, and
checks that Django migration history exists. If restoration fails, it removes only the new target
that it created. On success, the test database remains available for application and audit-chain
verification. Remove it only after documenting the test result and independently confirming the
exact target name.

## Full disaster recovery

Do not restore over the live database. Provision a clean database volume or replacement VM, run
the role-bootstrap step with newly generated database credentials, restore the selected snapshot,
apply only reviewed forward migrations, verify the audit chain against its external checkpoint,
and run application smoke tests. Cut over private access only after verification succeeds. Preserve
the failed system and logs until incident review is complete.

Hyper-V checkpoints and Docker volume copies are secondary conveniences, not substitutes for the
encrypted off-VM repository and a disconnected or independent copy.
