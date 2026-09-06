# PostgreSQL internal TLS

Status: implemented for the production Compose boundary; release-candidate evidence pending

## Security boundary

Every production TCP connection to PostgreSQL must use TLS 1.2 or TLS 1.3, validate the dedicated
internal certificate authority, and verify the server's exact Docker DNS identity, `db`. PostgreSQL
accepts password authentication only on `hostssl` records and explicitly rejects `hostnossl`
connections. The local health check uses a same-container Unix socket and does not cross a network
trust boundary.

The dedicated authority is intentionally narrow:

- its private key stays in offline or removable administrator custody and never enters the
  deployment secret directory, VM runtime, container, image, environment, log, or repository;
- it signs only the PostgreSQL server identity for DNS name `db`;
- clients receive only the public CA certificate and use libpq `verify-full`;
- the server receives its leaf certificate and private key, but not the CA private key; and
- the nginx-to-Gunicorn hop remains a separately tracked HTTP gap. This database control does not
  imply that all internal service traffic is encrypted.

Database clients still authenticate with distinct file-mounted SCRAM passwords. Replacing those
long-lived credentials with certificate authentication is the next backend-authentication slice,
not part of this server-authentication control.

## Initial generation

Run generation on a trusted Linux administrator host with OpenSSL available. The authority path
below must be a mounted offline/removable location outside both the checkout and the production VM's
persistent storage. The deployment directory must already be root-owned, mode 0700, and owned by the
dedicated secret-reader group described in the main README.

```bash
secret_gid="$(getent group household-budget-secrets | cut -d: -f3)"
offline_authority_dir=/media/offline-custody/household-budget-postgres-ca-v1
sudo install -d -m 0700 -o root -g root "$offline_authority_dir"
sudo .venv/bin/python scripts/generate-postgres-tls.py \
  --authority-directory "$offline_authority_dir" \
  --deployment-directory /etc/household-budget/secrets \
  --secret-group-id "$secret_gid"
```

The command creates these files without printing their values:

| File | Location and mode | Consumer |
| --- | --- | --- |
| `postgres_ca_private_key` | Offline authority directory, 0600 | Offline issuer only |
| `postgres_ca_certificate` | Offline authority directory, 0644; deployment directory, 0440 | Issuer and approved clients |
| `postgres_server_certificate` | Deployment directory, 0440 | PostgreSQL server |
| `postgres_server_private_key` | Deployment directory, 0440 | PostgreSQL server |

Unmount and secure the offline authority immediately after generation. Never add its private key to
the production secret directory to simplify renewal. The generator refuses an existing output,
uses exclusive nonsymlink file creation, removes partial installed outputs after failure, generates
a P-256 authority and P-256 server key, limits the leaf to server authentication and DNS SAN `db`,
and verifies its chain and at least 30 remaining validity days before installation.

## Runtime enforcement

`deploy/postgres/start-tls.sh` is the database entrypoint. It validates the read-only secret inputs,
copies the leaf and key into database-only tmpfs, changes them to PostgreSQL ownership and mode 0600,
then starts PostgreSQL with TLS 1.2–1.3 and the fixed external HBA policy. The CA private key is never
present. Every production Django, backup, restore, bootstrap, rotation, migration, integrity,
notification, and cleanup client has both:

```text
PGSSLMODE=verify-full
PGSSLROOTCERT=/run/secrets/postgres_ca_certificate
```

Production Django settings independently require the same validated single-certificate PEM path.
The pentest Compose stack remains a synthetic, isolated exception and is not a production deployment
path.

Run the disposable production-boundary proof after generation and before release:

```bash
./scripts/run-network-boundary.sh
```

The proof builds the real production images, checks exact Compose and runtime mounts, confirms the
live Django database session reports TLS 1.2 or TLS 1.3, verifies the server identity file modes,
and requires an explicit `sslmode=disable` connection to fail. Preserve only its pass/fail summary;
do not capture secret files, certificate PEM, private keys, or unsanitized container metadata.

## Rotation and expiry

The generated server leaf is valid for 397 days. Schedule a complete dedicated-authority rotation
before expiry; do not wait for the 30-day generator guard. Use new empty offline and deployment
staging directories because the generator never overwrites existing material.

1. Generate a new authority, leaf, and server key in the new staging locations.
2. Verify the offline authority is secured and its private key is absent from deployment staging.
3. Stop ingress and every database client. Keep a protected rollback copy of the current three
   deployment certificate files.
4. Promote the new public CA, server certificate, and server private key together. Do not mix
   generations.
5. Recreate PostgreSQL and every client so no old mount survives.
6. Run the disposable production-boundary proof and the application health, migration, backup,
   restore, and audit-integrity checks.
7. After the rollback window closes, destroy the retired deployment key and prior offline authority
   key. Record only sanitized issuer, subject class, validity, public-key algorithm, fingerprint,
   and test outcome in protected release evidence.

An interrupted or failed promotion is fail-closed: keep traffic stopped, restore the complete prior
three-file set, recreate the affected containers, and repeat validation. Never weaken `verify-full`,
add a broad CA bundle, or permit plaintext TCP to recover availability.

## Compromise response

Treat disclosure of either the CA private key or server private key as a security incident. Stop
ingress and database clients, preserve bounded evidence, generate an entirely new dedicated
authority and server identity on a known-good administrator host, promote them as one set, and prove
the retired CA is no longer trusted. A server-key disclosure does not by itself reveal database
passwords or encrypted backup keys, but review database and container logs for unauthorized sessions
and rotate database credentials when exposure or misuse cannot be ruled out. Follow
`docs/INCIDENT_RESPONSE.md` for notification, evidence, and broader credential rotation.
