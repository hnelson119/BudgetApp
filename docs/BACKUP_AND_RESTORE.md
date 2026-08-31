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
values or financial records. After all backup and retention steps succeed, it atomically updates a
mode-`0600` `.last-success` marker containing only a timestamp and release identifier. The
notification job mounts the repository read-only and uses only this marker's freshness; it never
receives Restic or database-backup credentials and cannot read application data from a dump.

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

Install the notification evaluator after the backup repository mount is available:

```bash
sudo install -m 0644 deploy/systemd/household-budget-notifications.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/household-budget-notifications.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now household-budget-notifications.timer
```

It runs every 30 minutes and creates a critical in-app alert when the success marker is missing or
older than `BUDGET_BACKUP_MAX_AGE_HOURS` (36 hours by default). A failed run never refreshes the
marker, so the alert becomes visible without putting backup secrets in the web application.

Install the independent staged-CSV cleanup timer as part of the same production maintenance setup:

```bash
sudo install -m 0644 deploy/systemd/household-budget-import-cleanup.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/household-budget-import-cleanup.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now household-budget-import-cleanup.timer
```

It runs hourly with a randomized delay. The runtime database identity marks unfinished imports
older than `CSV_IMPORT_STAGING_RETENTION_HOURS` (24 by default) abandoned, scrubs their bounded raw
cells, and appends a protected system audit event. It receives no backup, audit-signing,
administrator, or migration credentials. Review failures with
`systemctl status household-budget-import-cleanup.service`; do not raise the retention setting
above 720 hours.

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

## Independent audit checkpoints

Audit checkpoints are separate from Restic backups so restoring a modified database cannot silently
establish a new history. `BUDGET_AUDIT_CHECKPOINT_DIRECTORY` must be an existing off-VM mount and is
bound only into the short-lived `integrity` container. That container verifies each complete chain,
writes a canonical HMAC-SHA256 checkpoint with mode `0600`, and records the external filename and
signature metadata through a narrowly scoped database function.

Run it manually after the first household is provisioned:

```bash
docker compose --profile maintenance run --rm integrity
```

Install the daily timer after reviewing its paths:

```bash
sudo install -m 0644 deploy/systemd/household-budget-integrity.service /etc/systemd/system/
sudo install -m 0644 deploy/systemd/household-budget-integrity.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now household-budget-integrity.timer
```

Keep an independent protected copy of `audit_checkpoint_signing_key`, or mount that key read-only
from outside the VM when practical. During restore, verify the selected checkpoint's signature,
configured key ID, expected household ID, complete event chain, event count, sequence, and chain
head against the restored database before cutover. A missing, invalid, or mismatched checkpoint is
an incident signal, not a condition to silently overwrite.

With the integrity service pointed at the restored database, perform that comparison using the
checkpoint filename (paths and traversal are rejected):

```bash
docker compose --profile maintenance run --rm integrity \
  python manage.py verify_audit_checkpoint \
  audit-<household>-<timestamp>-sequence-<n>.checkpoint.json \
  --household-id <expected-household-uuid>
```
