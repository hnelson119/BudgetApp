# Cryptographic agility audit

BudgetApp inventories every cryptographic profile used by production, deployment, compatibility,
and tests in `docs/cryptographic-inventory.json`. This audit records how each of the 15 profiles is
selected, how persisted or external artifacts identify it, and what an algorithm or parameter
replacement requires. It does not claim that a future replacement algorithm is already approved.

| Profile | Selection and artifact boundary | Replacement or migration path |
| --- | --- | --- |
| `django-pbkdf2-hmac-sha256` | Django's ordered `PASSWORD_HASHERS`; encoded password strings contain the algorithm and rounds | Add the approved replacement ahead of the old hasher; successful authentication rewrites an old encoding, and forced resets cover inactive accounts |
| `fernet-v1` | MFA ciphertext now uses a `fernet-v1$` envelope and an authenticated payload profile plus a monotonic key version | The guarded rotation accepts legacy unprefixed rows, decrypts every row before writing, and atomically rewrites them in the current tagged format under the replacement key |
| `hmac-sha256` | Django signing is framework selected; audit checkpoints store document version, algorithm, and key ID | Django signing-key replacement intentionally invalidates sessions. Checkpoint key rotation preserves old documents and offline verification keys, but adding a second checkpoint MAC algorithm still requires an explicit verifier registry |
| `sha256` | Purpose-specific source sites and versioned artifact policies select SHA-256 | Each persisted format must version its digest transition. The inventory and hash policy locate every call, but a shared digest-profile registry does not yet cover all application fingerprints |
| `totp-hmac-sha1` | RFC 6238 provisioning explicitly declares SHA1 | This interoperability profile changes through MFA reset and re-enrollment with a newly approved authenticator profile; existing seeds are never silently reinterpreted |
| `password-blocklist-sha1` | Versioned offline corpus metadata fixes the compatibility digest and authenticates the payload with SHA-256 | Build and atomically install a new versioned corpus before changing the lookup format; no password-derived value leaves the host |
| `os-csprng` | Python `secrets` and approved provider generators | Replace the dependency/provider implementation and regenerate affected ephemeral or purpose-specific material; no persisted random-stream format exists |
| `restic-scrypt` | Restic's authenticated, self-describing repository key records contain salt and work parameters | `restic key passwd` creates a new wrapping record and the rehearsal proves new access, old rejection, integrity, and restore |
| `restic-aes256-ctr-poly1305-aes` | Pinned Restic repository format | Master-key or algorithm compromise requires a new repository and complete re-encryption of retained snapshots before the old repository is retired |
| `tls12-tls13` | Tailscale Serve provider policy and release observation | Provider-managed certificate/protocol replacement is accepted only after sanitized release observation; the repository cannot migrate provider state |
| `postgres-internal-tls` | PostgreSQL startup, libpq, certificates, and trust files | Generate a complete staged CA/server/client set, stop clients, atomically replace the set, recreate services, and rerun the production-boundary proof |
| `internal-web-mtls` | Gunicorn SSL context and nginx upstream TLS settings | Generate and stage both authorities and leaf identities, stop ingress, replace the six-file set, recreate services, and rerun the boundary proof |
| `tailscale-wireguard-suite` | Provider-managed Tailscale transport | Provider/device replacement occurs by expiring the old node and enrolling a fresh node; algorithm-suite migration remains provider controlled |
| `ssh-approved-suite` | Operating-system SSH policy and authorized public keys | Add and verify a replacement key from a second approved device before removing old authorization; release evidence must record the active approved suite |
| `test-md5-password-hasher` | Test settings only; hardened settings prohibit it | It has no production migration path or security claim and must remain isolated from production, migration, backup, and release-candidate settings |

## Enforced MFA format transition

New MFA ciphertext is emitted as `fernet-v1$<token>`. The authenticated token payload repeats the
profile, user ID, and key version. Reads fail closed for an unknown outer or inner profile while
continuing to accept the previous unprefixed Fernet rows. The existing all-row key-rotation
transaction therefore doubles as the format migration: it proves every legacy row decrypts before
writing any row, then rewrites all rows with the tagged profile or rolls the transaction back.

## Remaining V11.2.2 work

V11.2.2 remains partial. The audit identified the next concrete repository gaps:

- audit checkpoint verification dispatches only `HMAC-SHA256`; its tagged algorithm and key ID
  preserve historical interpretation, but there is no approved multi-algorithm verifier registry;
- purpose-specific SHA-256 fingerprints are completely inventoried, but their persisted formats do
  not share an exhaustive version-and-migration registry;
- provider-managed Tailscale and operating-system SSH suite changes require dated release evidence
  and cannot be proven solely from this checkout.

Do not promote the control until every security-purpose profile has a fail-closed replacement mode
and every persisted cryptographic artifact has a tested compatibility, invalidation, or migration
path. Future profiles must first be approved in the cryptographic inventory and hash policy.
