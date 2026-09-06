# Cryptographic inventory and maintenance

Status: implemented inventory; deployment evidence pending
Inventory reviewed: 2026-09-05
Next scheduled review: 2026-12-04

## Purpose and authority

`docs/cryptographic-inventory.json` is the canonical machine-readable inventory for cryptographic
keys, algorithms, certificates, and intentionally absent certificate boundaries. This runbook
explains how to maintain it without committing sensitive values. Together they implement the
repository-deliverable portion of ASVS `v5.0.0-11.1.2`; they do not claim that the future release
candidate or private Linux VM has been verified.

The release owner reviews the inventory at least every 90 days and for every release candidate.
Review it immediately when application or infrastructure cryptography changes, a key or certificate
consumer changes, a pinned cryptographic dependency or provider changes, or an incident affects
cryptographic material. The quality gate fails after the recorded review is overdue.

Never record an actual key, password, seed, recovery code, certificate, hostname, account, private
address, or unrestricted security report here. Release evidence may record a public certificate's
sanitized issuer, validity dates, public-key algorithm, and fingerprint in the protected evidence
location defined by the release process; it must not contain the private key or real household data.

## Ownership boundaries

The inventory distinguishes three boundaries:

- **Application:** Django selects or directly invokes the primitive. The repository pins the
  dependency, parameters, permitted uses, and prohibited uses.
- **Deployment:** a networkless maintenance tool or hardened host owns the key. Application
  containers receive only their explicitly mounted material.
- **Provider:** Tailscale, WireGuard, Let's Encrypt, browser trust stores, or operating-system SSH
  tooling select or operate the primitive. The application cannot read these private keys; the
  release process validates the live outcome.

The test-only MD5 password hasher is intentionally inventoried as an exception. It speeds synthetic
unit tests and is prohibited from every hardened, production-derived, browser, pentest, and release
target. Production stays on Django 5.2.17's primary PBKDF2-HMAC-SHA256 hasher with 1,000,000
iterations. A dependency update must update the inventory and its tests in the same change.

## Current key and certificate map

| Material | Owner and location | Permitted purpose | Must never protect |
| --- | --- | --- | --- |
| Django signing key | Root-owned file; approved Django containers only | Framework signing and domain-separated keyed identifiers | MFA seeds, backups, or audit checkpoints |
| MFA encryption key | Root-owned file; approved Django consumers only | Domain-separated Fernet encryption of TOTP seeds | Passwords, financial records, backups, or checkpoints |
| Per-user TOTP seed | Fernet ciphertext in PostgreSQL plus member authenticator | TOTP for exactly one member account | Data encryption, logs, or another account |
| Audit checkpoint key | Independent protected file; integrity container only | HMAC-SHA256 checkpoint authentication under its key ID | Runtime signing, backup encryption, or rewritten history |
| Restic repository password | Backup secret file plus off-VM recovery copy | scrypt-based unlocking of Restic master keys | Django, database, or application-field cryptography |
| Restic master keys | Wrapped Restic repository key files | Repository encryption and authentication | Any use outside the pinned Restic implementation |
| Tailscale node keys | Tailscale state on approved devices and VM | Tailnet identity and WireGuard transport | Application data at rest or shared identities |
| Tailscale Serve and ACME keys | Tailscale daemon state on VM | Exact-hostname private HTTPS | Funnel, application signing, or data at rest |
| SSH administrator and host keys | Administrator devices and VM | Key-only VM administration over Tailscale | Application login or shared administration |
| PostgreSQL internal CA key | Offline/removable administrator custody only | Sign the dedicated `db` server identity | Client issuance, browser trust, data encryption, or VM/container residency |
| PostgreSQL server key | Root-owned deployment secret copied into database-only tmpfs | Authenticate `db` and protect internal database TCP | Client authentication, browser TLS, or data at rest |
| PostgreSQL internal CA certificate | Approved database clients | Exact private trust anchor for `db` | Broad internal, browser, or public trust |
| PostgreSQL server certificate | PostgreSQL database container | DNS-constrained internal server authentication | Any identity other than `db` or any client role |
| Tailscale Serve certificate | Provider-managed VM state | Publicly trusted HTTPS for the exact neutral hostname | Other names, public exposure, or data-at-rest protection |
| Browser trust roots | Approved device trust stores | Validate the HTTPS certificate chain | Custom bypasses or self-signed production trust |

The JSON inventory is authoritative for exact algorithms, parameters, consumers, protected data,
excluded data, rotation, retirement, and evidence. Notably, the compatibility-only SHA-1 uses are
strictly bounded to RFC 6238 TOTP and full-digest local breached-password membership. SHA-1 is not
used for password storage, signatures, or integrity. Restic's repository profile and the
Tailscale/WireGuard provider profiles are recorded with their upstream specifications rather than
silently treated as opaque products.

## Review procedure

1. Start from a clean, reviewed release branch. Run `python scripts/check_cryptographic_inventory.py`
   and retain only its pass/fail result; the inventory itself contains no live values.
2. Search application, deployment, and configuration sources for hashing, MAC, signing, KDF,
   encryption, random generation, TLS, SSH, certificates, key files, and new secret mounts. Compare
   every result to the stable IDs in the JSON inventory.
3. Inspect dependency and container pins. Confirm Django's production hasher algorithm and work
   factor, the cryptography/Fernet version, Restic version and repository format, and the deployed
   Tailscale/OpenSSH versions. Update parameters and upstream HTTPS references when behavior changes.
4. Compare every Compose secret mount to the inventory. Database passwords are credentials rather
   than cryptographic keys, but any new use of one as key material is prohibited until separately
   inventoried and reviewed.
5. On the release VM, run the private-ingress preflight. Record only sanitized certificate issuer,
   validity, public-key algorithm, fingerprint, negotiated TLS version/cipher, and the SSH public-key
   algorithms actually enabled. Do not commit the real hostname or private material.
6. Confirm each key still has a single documented purpose, explicit consumers, prohibited uses,
   rotation procedure, and retirement rule. Trace discrepancies as security findings rather than
   changing evidence to match an unexplained deployment.
7. Review the known absences. PostgreSQL server TLS is inventoried and enforced; the
   nginx-to-Gunicorn HTTP hop and application client-certificate authentication remain tracked gaps.
   Add a certificate only when it actually exists and is validated.
8. Set `inventory_updated` to the review date and `next_review_due` to exactly 90 days later. Update
   the human-readable dates together, run the full quality gate, and obtain security review.

## Rotation and incident rules

Use `docs/INCIDENT_RESPONSE.md` for staged rotation. Purpose separation is mandatory: rotating one
material class never authorizes substituting another class. Django signing-key rotation deliberately
invalidates old sessions. MFA rotation transactionally re-encrypts every seed under a monotonically
higher key version. Audit checkpoint rotation retains the old verification key offline under its
original ID. A Restic password rotation rewraps repository master keys; suspected master-key
disclosure instead requires a new repository and full re-encryption. The PostgreSQL CA stays
offline; its leaf key reaches only database-owned tmpfs and rotates with the complete dedicated
trust set. Tailscale Serve and SSH private keys stay outside application containers and are revoked
at their owning control plane or host.

After a compromise, preserve required evidence before deletion, isolate affected consumers, replace
the material from a known-good environment, prove retired access fails, and complete the applicable
backup/restore, audit-chain, session-replay, MFA, certificate, and private-ingress checks.

## Known gaps

This inventory is complete for the current design, including things that are intentionally absent.
It does not make missing controls pass. Production PostgreSQL server TLS is implemented with exact
CA and hostname trust plus plaintext rejection, but the nginx-to-Gunicorn hop remains HTTP and
database clients still authenticate with long-lived file-mounted passwords. ASVS
`v5.0.0-12.3.1` and `v5.0.0-12.3.4` therefore remain partial, while `v5.0.0-12.3.3` and
`v5.0.0-13.2.1` remain not started. Browser trust, Tailscale, and SSH observations remain
release-only evidence on the real Linux VM. No reusable Tailscale auth key or application
client-certificate PKI currently exists.
