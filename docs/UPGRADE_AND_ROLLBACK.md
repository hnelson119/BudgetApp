# Upgrade and rollback runbook

Use this runbook from a trusted administrator console on the private Linux VM. An upgrade is not a
`git pull` followed by an unattended restart: bind every attempt to one reviewed commit, preserve a
verified pre-upgrade recovery point, and keep the previous release available until the observation
window closes. Never put a password, encryption key, cookie, recovery code, or database row in the
release record or a shell argument.

## 1. Two distinct rollback paths

- **Application-only rollback:** restart the previous application release against the upgraded
  database only when every migration in the candidate is explicitly backward-compatible. Do not run
  the previous release's migrations and do not reverse the candidate migration.
- **Database rollback:** when compatibility is uncertain, a migration is destructive, or post-
  migration data may be invalid, restore the verified pre-upgrade encrypted snapshot into a new
  database target. Never restore over, drop, truncate, or reverse-migrate the source database.

Treat an in-place reverse migration as unavailable for household financial data unless that exact
reverse operation has received a separate review and disposable PostgreSQL proof. A migration being
syntactically reversible in Django is not enough.

## 2. Release identity and prerequisites

Record the candidate and previous full Git commit IDs, operator, start time, approved maintenance
window, backup snapshot/time, checkpoint filenames, expected database migration plan, and rollback
decision. Keep a clean, detached checkout for each release under a protected VM release directory;
do not deploy from a mutable working tree or a branch name.

Before stopping service:

1. Confirm the candidate's quality, browser, restore, upgrade, and High/Critical image-scan checks
   passed for that exact commit.
2. Review every new migration. Classify additive changes as backward-compatible only when the
   previous application can safely ignore them. Split destructive changes into a later release.
3. Confirm the off-VM repository and external checkpoint directory are mounted and writable only by
   their maintenance identities.
4. Confirm all current services are healthy, audit chains verify, enough disk space exists for both
   database states, and no import or financial operation is in progress.
5. Preserve the previous source checkout, Compose configuration, image digests, and nonsecret
   settings. Do not copy or cache its secrets into the release directory.

## 3. Create the rollback point

Stop the four scheduled maintenance timers so they cannot overlap the cutover:

```bash
sudo systemctl stop household-budget-backup.timer
sudo systemctl stop household-budget-integrity.timer
sudo systemctl stop household-budget-notifications.timer
sudo systemctl stop household-budget-import-cleanup.timer
```

Write and independently verify the latest signed checkpoints, then create the encrypted backup:

```bash
docker compose --profile maintenance run --rm integrity
docker compose --profile maintenance run --rm backup
```

Follow `docs/BACKUP_AND_RESTORE.md` to run `restic check`, verify the `.last-success` release marker,
and confirm checkpoint signatures. Abort if any command fails, the backup is stale, the expected
release tag is absent, or a checkpoint does not match. Record only snapshot/checkpoint references
and pass/fail outcomes.

## 4. Stage and apply the candidate

From the clean candidate checkout, set `APP_RELEASE` to its full commit ID and render Compose before
changing the live service. `BUDGET_SECRET_DIR` must continue to reference the protected external
secret directory; no secret belongs in the checkout or `.env`.

```bash
export APP_RELEASE=<candidate-full-commit>
docker compose config --quiet
docker compose build web migrate ingress notify import-cleanup integrity
docker compose stop ingress web
docker compose --profile maintenance run --rm db-bootstrap
docker compose --profile maintenance run --rm migrate
docker compose up -d db web ingress
```

The dedicated migration role applies the schema while the runtime role remains unable to alter it.
Do not start the candidate web service if migration output is ambiguous or incomplete. After startup,
require all of the following before reopening the maintenance window:

- `docker compose ps` reports the database and web path healthy;
- the private HTTPS `/health/live/` response is safe and ready;
- password-plus-MFA login works from an approved device;
- dashboard, current pay period, one read-only audit view, and one representative record from each
  financial area load without changing data;
- complete audit-chain and signed-checkpoint verification still pass;
- logs show the candidate `APP_RELEASE` and contain no credential, request body, financial value, or
  raw exception page.

Restart the four timers only after these checks pass. Observe the candidate through at least one
notification/import-cleanup interval and one verified backup before deleting the previous release.

## 5. Application-only rollback

Use this path only when the reviewed migration plan is additive and the previous release has already
passed against the candidate schema in rehearsal.

1. Stop `ingress` and `web`; leave PostgreSQL running and do not invoke `migrate`.
2. From the preserved previous-release checkout, set `APP_RELEASE` to the previous full commit,
   rebuild or select its recorded images, and start `web` and `ingress`.
3. Repeat the health, approved-device login, read-only financial smoke, audit-chain, checkpoint, and
   sanitized-log checks.
4. Keep the candidate backup and both release directories while the failure is investigated.

If the previous application cannot become healthy against the forward schema, stop it and use the
clean-database rollback below. Do not experiment with reverse migrations on the source database.

## 6. Clean-database rollback

Choose a new database name matching `household_budget_restore_<label>`. With the candidate services
stopped, use the recovery profile and the pre-upgrade snapshot:

```bash
RESTORE_TARGET_DB=household_budget_restore_<label> \
RESTORE_SNAPSHOT_ID=<pre-upgrade-snapshot-id> \
docker compose --profile recovery run --rm restore-verify

POSTGRES_DB=household_budget_restore_<label> \
docker compose --profile maintenance run --rm db-bootstrap
```

The verifier refuses the configured live database and any existing target. Against the new target,
verify the multi-household data, complete audit chains, external signed checkpoints, migration
history, and previous-release health before cutover. Then update only the nonsecret `POSTGRES_DB`
deployment setting, recreate `web`, `ingress`, and maintenance services from the previous release,
and repeat all smoke checks. Keep the upgraded source database isolated and read-only for incident
analysis and later reconciliation; do not silently copy post-backup writes into the restored target.

## 7. Failure and evidence rules

Abort or roll back when a migration fails, an image or dependency scan reports unresolved
High/Critical risk, the health endpoint is not ready, audit/checkpoint verification changes, a
cross-household check fails, the runtime identity gains schema privileges, secrets appear in logs,
or the previous release cannot read the candidate schema as planned.

The sanitized record may contain release IDs, image digests, snapshot/checkpoint references,
timestamps, operator, elapsed recovery time, outcomes, and finding IDs. Store raw logs and command
transcripts only in the encrypted assessment location outside the repository. Remove temporary
rollback targets only after the release owner explicitly closes the observation window.

## 8. Disposable rehearsal

Before the real VM exercise, run:

```powershell
.\scripts\run-upgrade-rehearsal.ps1
```

On Linux use `./scripts/run-upgrade-rehearsal.sh`. The fixed disposable project creates synthetic
data, checkpoints and encrypts the baseline, mounts a test-only additive migration into the
candidate, proves both candidate health and previous-app compatibility with the forward schema, and
then restores the pre-upgrade snapshot into a new database. It proves the candidate marker is absent,
the fixture and checkpoints match, and the previous application becomes healthy on that restored
target before removing every generated credential, database, repository, container, network, and
volume.

This is production-path development evidence, not the real deployment gate. It uses one current code
base with a test-only migration to exercise orchestration safely. The clean VM exercise must still use
two preserved release artifacts, the real off-VM repository, observed downtime/recovery time, private
TLS, approved-device login, and a sanitized release-candidate evidence record.
