# PostgreSQL mutual TLS and certificate authentication

Status: implemented for the production Compose boundary; release-candidate evidence pending

## Security boundary

Every production TCP connection to PostgreSQL must use TLS 1.2 or TLS 1.3, validate the dedicated
server certificate authority, verify the exact Docker DNS identity `db`, and present a purpose-bound
client certificate from a separate client authority. PostgreSQL accepts only the fixed certificate
identity map on `hostssl`, explicitly rejects `hostnossl`, and stores no password verifier for any
non-built-in login role. The same-container health check uses a local Unix socket and does not cross
a network trust boundary.

The two authorities have deliberately separate purposes:

- the server CA signs only the PostgreSQL server identity for DNS name `db`;
- the client CA signs only the nine fixed production service identities;
- both CA private keys remain in offline or removable administrator custody and never enter the
  deployment directory, VM runtime, container, image, environment, log, or repository;
- clients receive the public server CA plus only their own leaf and private key;
- PostgreSQL receives its server leaf and key plus only the public client CA; and
- the independently purpose-bound nginx-to-Gunicorn mutual-TLS authorities and identities cannot
  be substituted for any PostgreSQL authority, server, or client identity.

The isolated synthetic pentest stack remains password-based so credential recovery can be
rehearsed without weakening production. It is not a production deployment path.

## Initial generation

Run generation on a trusted Linux administrator host with OpenSSL available. The authority path
must be a mounted offline/removable location outside both the checkout and the production VM's
persistent storage. The deployment directory must already be root-owned, mode 0700, and associated
with the dedicated secret-reader group described in the main README.

```bash
secret_gid="$(getent group household-budget-secrets | cut -d: -f3)"
offline_authority_dir=/media/offline-custody/household-budget-internal-tls-authorities-v1
sudo install -d -m 0700 -o root -g root "$offline_authority_dir"
sudo .venv/bin/python scripts/generate-postgres-tls.py \
  --authority-directory "$offline_authority_dir" \
  --deployment-directory /etc/household-budget/secrets \
  --secret-group-id "$secret_gid"
```

The command creates all production internal-TLS material without printing its values. Its
PostgreSQL outputs are:

| File class | Location and mode | Consumer |
| --- | --- | --- |
| `postgres_ca_private_key` | Offline authority, 0600 | Server issuer only |
| `postgres_ca_certificate` | Offline authority, 0644; deployment, 0440 | Server issuer and approved clients |
| `postgres_client_ca_private_key` | Offline authority, 0600 | Client issuer only |
| `postgres_client_ca_certificate` | Offline authority, 0644; deployment, 0440 | Client issuer and PostgreSQL |
| `postgres_server_certificate`, `postgres_server_private_key` | Deployment, 0440 | PostgreSQL only |
| `postgres_<service>_client_certificate`, `postgres_<service>_client_private_key` | Deployment, 0440 | Exactly one named service |

The client service prefixes are `db_bootstrap`, `migrate`, `mfa_key_rotate`, `backup`, `integrity`,
`notify`, `import_cleanup`, `restore_verify`, and `web`. Unmount and secure the offline authorities
immediately after generation.

The same guarded invocation also creates separate Gunicorn-server and nginx-client authorities,
the DNS-constrained `web` server identity, and the sole `budget-ingress` client identity. Their
deployment files are `gunicorn_ca_certificate`, `gunicorn_client_ca_certificate`,
`gunicorn_server_certificate`, `gunicorn_server_private_key`, `nginx_client_certificate`, and
`nginx_client_private_key`; both additional CA private keys remain only in the authority directory.
They are documented and rotated as an independent trust set in `docs/PRIVATE_INGRESS.md`.

The generator refuses existing output and symlink directories, uses exclusive nonsymlink file
creation, and removes partially installed output after failure. It generates separate P-256 CAs,
a P-256 server leaf constrained to server authentication and DNS SAN `db`, and unique P-256 client
leaves constrained to client authentication. Every 397-day leaf is chain- and purpose-validated and
must have at least 30 remaining validity days before installation.

## Exact identity-to-role map

`deploy/postgres/start-tls.sh` validates the configured role identifiers and writes the exact map
below into database-only tmpfs before PostgreSQL starts:

| Certificate CN | Production service | Mapped database role |
| --- | --- | --- |
| `budget-db-bootstrap` | `db-bootstrap` | administrator |
| `budget-restore-verify` | `restore-verify` | administrator |
| `budget-migrate` | `migrate` | migration |
| `budget-backup` | `backup` | backup |
| `budget-integrity` | `integrity` | audit |
| `budget-web` | `web` | runtime |
| `budget-notify` | `notify` | runtime |
| `budget-import-cleanup` | `import-cleanup` | runtime |
| `budget-mfa-key-rotate` | `mfa-key-rotate` | runtime |

No wildcard or fallback mapping is allowed. Possessing one service key cannot authenticate as a
different role. `db-bootstrap` creates or updates each login role with `PASSWORD NULL` and fails if
any non-built-in login role retains a password verifier.

## Runtime enforcement and proof

Every client uses these libpq controls, with a distinct certificate and key path:

```text
PGSSLMODE=verify-full
PGSSLROOTCERT=/run/secrets/postgres_ca_certificate
PGSSLCERT=/run/secrets/postgres_<service>_client_certificate
PGSSLKEY=/run/secrets/postgres_<service>_client_private_key
```

Production Django settings separately validate the root certificate, client certificate, and
private-key paths during settings loading and do not configure a database password. The database
startup wrapper copies its three public/secret TLS inputs and generated identity map into mode-0600
PostgreSQL-owned tmpfs, then starts PostgreSQL with the dedicated CA, exact HBA, and TLS 1.2–1.3.
The official image requires `POSTGRES_HOST_AUTH_METHOD=trust` only while initializing a fresh data
directory without a password; its generated data-directory HBA is never active because every
server start is pinned to the repository's external certificate-only `hba_file`. The boundary probe
checks both the wrapper and that exact active HBA.

Run the disposable production-boundary proof before release:

```bash
./scripts/run-network-boundary.sh
```

The proof builds the real production images and checks exact Compose/runtime mounts, root-owned
mode-0440 source secrets, the live HBA and identity map, staged mode-0600 files, and the negotiated
TLS version and `budget-web` client DN. It requires plaintext, absent-client-certificate, and
web-certificate-as-audit-role attempts to fail, and confirms directly that no production login role
has a password verifier. Preserve only its pass/fail summary; never capture PEM, private keys, or
unsanitized container metadata.

## Rotation and expiry

All generated leaves are valid for 397 days. Schedule a complete rotation before expiry; do not
wait for the 30-day generator guard. Use new empty authority and deployment staging directories
because the generator never overwrites material.

1. Generate the replacement internal authorities and the complete server/client leaf sets.
2. Verify every CA private key is secured offline and absent from deployment staging.
3. Stop ingress, PostgreSQL, and every database client. Keep a protected rollback copy of the
   complete current deployment certificate set.
4. Promote the new server CA, client CA, server pair, and all nine client pairs together. Never mix
   generations.
5. Recreate PostgreSQL and every client so no old mount survives.
6. Run the production-boundary proof plus migration, backup, restore, and audit-integrity checks.
7. After the rollback window closes, destroy retired deployment keys and offline CA keys. Record
   only sanitized issuer, subject class, validity, public-key algorithm, fingerprint, and outcome.

An interrupted promotion fails closed: keep traffic stopped, restore the complete prior set,
recreate affected containers, and repeat validation. Never weaken `verify-full`, add a broad trust
bundle, add a password HBA fallback, or loosen the identity map to recover availability.

## Compromise response

Treat disclosure of either PostgreSQL CA key, the server key, or any client key as a security incident. Stop
ingress and database clients, preserve bounded evidence, generate a complete replacement authority
and leaf set on a known-good administrator host, promote it atomically, and prove the retired client
and server identities are no longer trusted. Review database and container logs for unauthorized
sessions and follow `docs/INCIDENT_RESPONSE.md` for notification, evidence handling, application
secret rotation, and the deliberately separate pentest credential-recovery rehearsal.
