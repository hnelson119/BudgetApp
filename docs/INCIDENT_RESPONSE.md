# Incident response and credential-rotation runbook

This runbook is for the private Linux VM deployment. Use it from a known-good administrator device
and reviewed checkout. Never paste a reusable credential into a shell argument, `.env`, ticket,
chat, log, or Git. Secret values belong only in root-owned files under the mode-`0700`
`BUDGET_SECRET_DIR`; files are mode `0440` and readable only by root plus the dedicated numeric
container group. Keep the recovery copy and retired audit-verification keys outside the VM.

The disposable rehearsal in this repository is supporting development evidence. A release pass
still requires the selected release candidate, real VM, Tailscale administrator, two household
devices, timed observations, and a sanitized record in `docs/release-evidence.json`.

## 1. Decide scope before changing anything

Record the start time, operator, affected account/device/service, candidate commit, and a short
reason without copying secrets or financial data. Use the narrowest applicable response:

- Lost household device: revoke that Tailscale device, reset the affected app credentials, and
  verify the device can no longer reach or reuse a session.
- Exposed app or infrastructure credential: isolate its consumers and rotate that credential plus
  any credential it could read or administer.
- Suspected VM, Docker, root, database-administrator, backup-key, or audit-key compromise: stop
  ingress, disconnect the VM from the tailnet, preserve the collector-only security-log volume,
  other logs, and external checkpoints, and rebuild on a clean VM. Rotating in place is not
  sufficient assurance.
- Suspected data or audit manipulation: do not overwrite the system. Preserve the VM, verify the
  external checkpoint, and follow `docs/BACKUP_AND_RESTORE.md` into a new restore target.

Do not delete logs, sessions, containers, volumes, checkpoints, or the affected VM until the
evidence needed for review is preserved. Do not create a fresh audit checkpoint over an unexplained
chain failure.

After preserving the required evidence, an administrator can contain application-session replay
without changing credentials. The individual operation requires the account email as a separate
confirmation; the application-wide operation requires the exact fixed confirmation phrase. Both
operations increment the affected server-side session versions, remove stored authenticated and
pending-MFA sessions in the same transaction, emit a redacted security event, and append a protected
event to every affected household audit stream. They do not revoke a Tailscale device, reset a
password, reset MFA, or replace the broader incident steps below.

```bash
docker compose exec web python manage.py revoke_user_sessions \
  --email person@example.com \
  --reason "Suspected session compromise YYYY-MM-DD" \
  --confirm person@example.com

docker compose exec web python manage.py revoke_user_sessions \
  --all-users \
  --reason "Application-wide session containment YYYY-MM-DD" \
  --confirm revoke-all-sessions
```

The global form also removes anonymous stored sessions, so use it only when application-wide
containment is intended. Never place a session key, cookie value, password, authenticator value, or
other reusable credential in the reason.

## 2. Lost-device and account-recovery procedure

1. In the Tailscale administration console, expire or remove the exact lost device. If the device
   held an administrator identity, also revoke its SSH key and review Tailscale/identity-provider
   sessions. Do not revoke the other household member's device as a shortcut.
2. From the trusted VM console, reset the affected app password if it may have been saved or
   observed. The command prompts twice without echo, rejects reuse, applies Django password policy,
   increments the server-side session version, and appends a protected event:

   ```bash
   docker compose exec -it web \
     python manage.py reset_user_password person@example.com \
     --reason "Lost device incident YYYY-MM-DD"
   ```

3. Reset MFA even if the authenticator was protected by device biometrics. This deletes the seed
   and every recovery-code hash, increments the session version again, and records a separate
   protected event. Type the displayed email address to confirm:

   ```bash
   docker compose exec -it web \
     python manage.py reset_user_mfa person@example.com \
     --reason "Lost authenticator incident YYYY-MM-DD"
   ```

4. From an already trusted second device, prove an old browser session redirects to login. Prove
   the old password, TOTP, and one unused old recovery code are rejected. Do not record their
   values. Review the `auth.password_emergency_reset` and `auth.mfa_emergency_reset` events and
   verify the audit chain/checkpoint before re-enrollment.
5. Enroll a newly generated TOTP seed on the replacement device, save the newly displayed recovery
   codes offline, confirm them in the app, and complete a fresh password-plus-TOTP login.
6. Re-enroll the replacement device in Tailscale under the correct individual identity and role.
   Approval must restore only TCP 443 for the spouse role; it must not grant SSH, database, app
   upstream, or Docker access. Confirm the revoked device remains unable to connect.

If the second household device and offline recovery material are also unavailable, keep ingress
stopped until identity-provider and Tailscale ownership have been independently recovered. Do not
weaken MFA, tailnet policy, host validation, or the firewall to regain access.

## 3. Rotation rules shared by every secret

Before a planned rotation, create and verify a current encrypted backup and signed checkpoint.
Stop the relevant timer and every consumer of the credential. Generate a distinct random value into
`<secret>.next` with the same root ownership and mode as the current file; never write the value to
stdout. Keep a protected recovery copy until the new credential is verified. After the service-side
change succeeds, atomically promote the staged file, recreate affected containers, and prove both
that the new credential works and the retired credential fails.

For an incident, preserve evidence first and rotate from a known-good host. A credential that could
read another credential expands the rotation scope. Never rotate several database roles at once;
doing them one at a time keeps rollback bounded.

## 4. MFA encryption-key rotation

MFA seeds cannot survive a raw file replacement. The maintenance command decrypts every seed before
writing any row, refuses mixed/stale versions, re-encrypts all rows in one transaction, and appends
one protected `security.mfa_key_rotated` event per household. Existing sessions stay valid during a
planned cryptographic rotation; use the password/MFA recovery commands when revocation is intended.

1. Stop ingress/web and ensure notification/import jobs are not running. Stage
   `django_mfa_encryption_key.next`, retain a protected copy, and choose a version greater than
   `DJANGO_MFA_ENCRYPTION_KEY_VERSION`.
2. Run the transaction while the current key file and current version are still configured:

   ```bash
   BUDGET_MFA_NEXT_KEY_VERSION=2 \
   BUDGET_MFA_ROTATION_REASON="Scheduled MFA key rotation YYYY-MM-DD" \
   docker compose --profile maintenance run --rm mfa-key-rotate
   ```

3. On success, atomically replace `django_mfa_encryption_key` with the staged file and set
   `DJANGO_MFA_ENCRYPTION_KEY_VERSION=2` in the non-secret deployment environment. Recreate web and
   ingress, then complete a real login for both household members and verify the protected events.
4. If the command fails, the database remains on the old version; keep the old file and investigate.
   If the command succeeds but promotion is interrupted, keep services stopped and promote the
   exact staged/recovery copy. Do not rerun the version-1-to-2 command against version-2 rows.

## 5. PostgreSQL credential rotation

For `budget_runtime`, `budget_migration`, `budget_backup`, or `budget_audit`, stop only that role's
consumers, retain a protected copy of the current file, promote the role's staged `.next` file, and
run `docker compose --profile maintenance run --rm db-bootstrap` while the administrator credential
is unchanged. Recreate and test the affected consumer. If bootstrap fails, restore the retained
file before restarting it. The web service must never receive administrator, migration, backup, or
audit credentials.

The administrator role requires an in-database change; replacing its initialization file alone
does not change an existing PostgreSQL cluster. Stage `postgres_admin_password.next`, stop other
maintenance jobs, and run:

```bash
docker compose --profile maintenance run --rm db-admin-key-rotate
```

The helper reads both values from mounted files, changes the role without placing a password in an
argument or container definition, reconnects with the staged credential, and proves the retired
credential fails. Then atomically promote the staged file, recreate `db`, run `db-bootstrap`, and
test migration, runtime, backup, and integrity connections before deleting the temporary recovery
copy.

Treat disclosure of the PostgreSQL internal CA private key or server private key separately from a
password rotation. Stop ingress and database clients, preserve bounded evidence, and generate a new
dedicated CA, server certificate, and server key on a known-good administrator host by following
`docs/POSTGRES_TLS.md`. Promote the public CA, leaf, and server key as one generation, recreate the
database and every client, run the production-boundary proof, and confirm the retired CA is no
longer trusted. Never recover availability by weakening `verify-full` or allowing plaintext TCP.
Rotate database passwords too when the incident scope or observed sessions cannot rule out their
exposure.

## 6. Encrypted-backup repository key rotation

Restic repository passwords are encryption keys, not ordinary file settings. Stage
`restic_repository_password.next`, stop the backup timer, verify the latest snapshot exists, and
run:

```bash
docker compose --profile maintenance run --rm restic-key-rotate
```

The networkless helper uses Restic's validated `key passwd --new-password-file` operation, reopens
the repository with the staged file, runs `restic check`, and proves the retired password no longer
opens the repository. It changes repository access metadata, not snapshot data, so older snapshots
remain recoverable. On success, atomically promote the staged file, update the independent recovery
copy, run one backup, and perform a clean restore verification before restarting the timer. Never
replace the password file without changing the repository key first.

## 7. Django signing key and audit-checkpoint key

- Django signing key: stop ingress and every Django container, stage and atomically promote
  `django_secret_key`, then recreate the containers. This intentionally invalidates signed session
  data; prove old sessions fail and both users can complete fresh MFA logins. The key is never used
  as the MFA seed-encryption key.
- Audit checkpoint key: write and verify a final checkpoint with the old key ID. Archive the old key
  offline under that ID; it is required to verify historical checkpoints. Stage a new
  `audit_checkpoint_signing_key`, atomically promote it, increment `AUDIT_CHECKPOINT_KEY_ID`, write
  a new checkpoint, and verify it before restarting the integrity timer. Never relabel an old key,
  overwrite retired verification material, or treat a new checkpoint as proof of earlier history.

To verify an older checkpoint, mount only its matching retired key read-only into a one-off
integrity container and set both the matching key-file path and historical key ID. Keep that key
offline again immediately afterward. The web container must never receive current or retired
checkpoint keys.

## 8. Tailscale, SSH, and identity-provider credentials

Revoke device and login sessions before issuing replacements. Remove only the exact compromised SSH
public key from `authorized_keys`; do not enable password SSH. Avoid reusable Tailscale auth keys for
this two-person deployment. If one becomes necessary later, make it tagged, single-purpose,
preapproved, short-lived, and rotate it in the Tailscale console without storing it in this
repository or shell history. A compromised identity-provider administrator session requires
provider-side password/passkey/session recovery before the device is trusted again.

## 9. Verification and sanitized evidence

After containment or rotation, run the private-ingress preflight, audit-chain/checkpoint verification,
encrypted backup/restore check, and real password-plus-MFA smoke tests. Review bounded application,
the minimized collector alert summary, Tailscale, UFW, SSH, Docker, PostgreSQL, backup, and integrity
logs for the incident window:

```bash
docker compose exec -T security-log python -m core.security_log_collector review
```

Any warning-or-higher count requires triage against the restricted archive and escalation under the
scope rules above. Preserve the archive before container or volume cleanup. Record
only dates, operator, release, affected credential classes, pass/fail outcomes, finding IDs, recovery
time, and whether old access was rejected. Do not retain tokens, cookies, passwords, TOTP seeds,
recovery codes, private addresses, raw database rows, or financial values in Git.

Use the disposable development rehearsal before the real exercise:

```powershell
.\scripts\run-credential-rehearsal.ps1
```

On Linux use `./scripts/run-credential-rehearsal.sh`. It creates a fresh protected PostgreSQL
fixture, performs a versioned MFA re-encryption, restarts under the new key, resets a synthetic
password/MFA/session/recovery-code set, completes fresh enrollment and login, verifies both audit
chains, rotates the disposable PostgreSQL administrator password with retired-password rejection,
and removes every generated credential, container, network, and volume. The separate restore
rehearsal rotates the disposable Restic repository key and restores the pre-rotation snapshot with
the new key. Neither run substitutes for Tailscale revocation or the release-candidate VM exercise.
