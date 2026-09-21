# Cryptographic inventory and maintenance

Status: implemented inventory; deployment evidence pending
Inventory reviewed: 2026-09-06
Next scheduled review: 2026-12-05

## Purpose and authority

`docs/cryptographic-inventory.json` is the canonical machine-readable inventory for cryptographic
keys, algorithms, certificates, and intentionally absent cryptographic material. This runbook
explains how to maintain it without committing sensitive values. Together they implement the
repository-deliverable portions of ASVS `v5.0.0-11.1.1` and `v5.0.0-11.1.2`; they do not claim that
the future release candidate or private Linux VM has been verified.

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
target. Production explicitly selects Django 5.2.17's primary PBKDF2-HMAC-SHA256 hasher with
1,000,000 iterations. The dedicated policy pins every credential operation and rejects direct
password-field writes; see `docs/PASSWORD_HASHING_POLICY.md`. A dependency update must update both
inventories and their tests in the same change.

The dedicated approved hash-function policy source-derives every application and maintenance hash
selection, verifies Django's managed SHA-256 defaults, and bounds SHA-1 to the existing TOTP and
offline breached-password compatibility formats. See `docs/HASH_FUNCTION_POLICY.md` and
`docs/hash-function-policy.json`; a new algorithm or use must update both inventories together.

## Key-management policy

The key lifecycle follows NIST SP 800-57 Part 1 Revision 5. Every key class must pass through the
recorded generation, protected-distribution, activation, rotation, suspension or revocation,
retirement, and destruction phases. The JSON policy is authoritative for those phases and the
mandatory controls. A new key cannot be activated until this inventory records its independent
purpose, owner, algorithm and parameters, authorized consumers, protected storage and distribution,
rotation trigger and procedure, retirement rule, and recovery boundary.

A **trust entity** is one independently authorized runtime, provider, person, or device permitted to
perform cryptographic operations with secret or private material. Purpose-specific processes inside
the same hardened application boundary are one entity; a public key or certificate is not a secret
holder, and sealed recovery custody or file provisioning alone does not authorize cryptographic
use. A shared secret may be usable by at most two trust entities, and a private key by exactly one
active trust entity. Offline recovery and retired verification copies must remain sealed and
inactive; temporarily unsealing one is a separate, audited maintenance event and does not authorize
routine concurrent use. If a design needs broader sharing, it must use distinct per-entity keys
rather than waive this limit.

Generate independent, purpose-specific material with the operating-system CSPRNG or the documented
managed provider. Move it only through protected files, provider state, or direct enrollment—not
source control, logs, command lines, or ordinary environment values. Rotate when a documented
schedule expires, an owner or consumer changes, exposure is suspected, an algorithm or parameter is
deprecated, or a provider incident affects the material. For suspected exposure, isolate or revoke
affected consumers before replacement and prove retired access fails before reopening service.
Destroy retired material after its stated retention purpose ends; only keys explicitly needed for
historical verification or disaster recovery may remain sealed.

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
| PostgreSQL client CA key | Offline/removable administrator custody only | Sign the fixed service-client identities | Server issuance, browser trust, data encryption, or VM/container residency |
| PostgreSQL server key | Root-owned deployment secret copied into database-only tmpfs | Authenticate `db` and protect internal database TCP | Client authentication, browser TLS, or data at rest |
| PostgreSQL per-service client keys | Separate root-owned deployment secrets; one assigned client each | Authenticate one service to its mapped least-privilege role | Another service/role, server identity, browser TLS, or data at rest |
| PostgreSQL internal CA certificate | Approved database clients | Exact private trust anchor for `db` | Broad internal, browser, or public trust |
| PostgreSQL client CA certificate | PostgreSQL database tmpfs | Exact trust anchor for client authentication | Server, browser, public, or unrelated internal trust |
| PostgreSQL server certificate | PostgreSQL database container | DNS-constrained internal server authentication | Any identity other than `db` or any client role |
| PostgreSQL per-service client certificates | Exactly one assigned database client each | Exact CN-to-role authentication through the fixed map | Unmapped roles, server identity, or shared service authentication |
| Gunicorn server CA key | Offline/removable administrator custody only | Sign the dedicated `web` server identity | Client issuance, database/browser trust, or VM/container residency |
| nginx client CA key | Offline/removable administrator custody only | Sign the sole `budget-ingress` client identity | Server issuance, database/browser trust, or VM/container residency |
| Gunicorn server key and certificate | Root-owned secrets mounted only into `web` | Authenticate DNS name `web` and protect the internal HTTP hop | Client authentication, database TLS, browser TLS, or data at rest |
| nginx client key and certificate | Root-owned secrets mounted only into `ingress` | Authenticate the sole relay client to Gunicorn | Server identity, database TLS, browser TLS, or another client |
| Gunicorn server CA certificate | nginx ingress only | Exact private trust anchor for DNS name `web` | Broad internal, database, browser, or public trust |
| nginx client CA certificate | Gunicorn web service only | Exact trust anchor for the sole relay client | Server, database, browser, public, or unrelated internal trust |
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
4. Compare every Compose secret mount to the inventory. Confirm each database client receives only
   the PostgreSQL server CA and its own leaf/key pair; PostgreSQL receives only its server pair and
   public client CA; nginx receives only the Gunicorn server CA and its client pair; Gunicorn
   receives only its server pair and public nginx client CA; and no database password secret exists.
5. On the release VM, run the private-ingress preflight. Record only sanitized certificate issuer,
   validity, public-key algorithm, fingerprint, negotiated TLS version/cipher, and the SSH public-key
   algorithms actually enabled. Do not commit the real hostname or private material.
6. Confirm each key still has a single documented purpose, explicit consumers, prohibited uses,
   rotation procedure, and retirement rule. Trace discrepancies as security findings rather than
   changing evidence to match an unexplained deployment.
7. Review the known absences. PostgreSQL and nginx-to-Gunicorn mutual TLS are inventoried and
   enforced with independent trust sets. Add material only when it actually exists and its
   generation, consumer separation, and validation are covered by executable evidence.
8. Set `inventory_updated` to the review date and `next_review_due` to exactly 90 days later. Update
   the human-readable dates together, run the full quality gate, and obtain security review.

## Rotation and incident rules

Use `docs/INCIDENT_RESPONSE.md` for staged rotation. Purpose separation is mandatory: rotating one
material class never authorizes substituting another class. Django signing-key rotation deliberately
invalidates old sessions. MFA rotation transactionally re-encrypts every seed under a monotonically
higher key version. Audit checkpoint rotation retains the old verification key offline under its
original ID. A Restic password rotation rewraps repository master keys; suspected master-key
disclosure instead requires a new repository and full re-encryption. Both PostgreSQL CA keys stay
offline; the server key reaches only database-owned tmpfs and each client key reaches only its
assigned service. They rotate as one complete trust set. The Gunicorn server and nginx client CAs
also stay offline; their two leaves rotate together as a separate trust set. Tailscale Serve and SSH private keys stay
outside application containers and are revoked
at their owning control plane or host.

After a compromise, preserve required evidence before deletion, isolate affected consumers, replace
the material from a known-good environment, prove retired access fails, and complete the applicable
backup/restore, audit-chain, session-replay, MFA, certificate, and private-ingress checks.

## Known gaps

This inventory is complete for the current design, including things that are intentionally absent.
It does not make missing controls pass. Production PostgreSQL mutual TLS is implemented with exact
server trust, a separate client CA, unique service identities, fixed role mapping, and plaintext and
password rejection. The nginx-to-Gunicorn hop separately requires mutual TLS with exact CA and DNS
validation and no plaintext production listener. ASVS `v5.0.0-12.1.3`, `v5.0.0-12.3.3`,
`v5.0.0-12.3.4`, and `v5.0.0-13.2.1` are implemented. `v5.0.0-12.3.1` and
`v5.0.0-12.3.2` remain partial only because browser trust, Tailscale, and SSH observations remain
release-only evidence on the real Linux VM. No reusable Tailscale auth key exists.
