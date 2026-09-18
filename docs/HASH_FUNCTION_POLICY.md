# Approved hash-function policy

Status: implemented and enforced
Policy reviewed: 2026-09-13
Next scheduled review: 2026-12-12

## Boundary

`docs/hash-function-policy.json` is the authoritative source inventory for ASVS
`v5.0.0-11.4.1`. The application approves SHA-256 for general-purpose hashing, HMAC, framework
signing, certificate signatures, and fixed-length derivation from already-random key material.
SHA-512 is approved for npm dependency-integrity metadata. Both functions provide at least 256 bits
of output; neither is approved as an unkeyed password hash or as proof of authenticity without a
secret key or signature.

The executable checker discovers every direct Python `hashlib`, `hmac`, Django signing, Django
`salted_hmac`, and OpenSSL hash selection in production, maintenance, and release-test source. It
also scans production scripts and templates, browser and deployment helpers, and shell/PowerShell
source for Node hash calls, Web Crypto operations, and checksum commands. The
current inventory contains 35 operations across 26 files. A new call, dynamic algorithm selection,
module alias, direct weak-hash import, or undocumented operation fails both quality gates. This
reviewed API inventory supplements code review; it is not a general proof against arbitrary custom
cryptographic implementations or all possible language indirection.

Framework and provider-owned primitives are separately bounded. The checker verifies the pinned
Django version and its SHA-256 signing, token, and PBKDF2 PRF defaults at runtime. Fernet's
HMAC-SHA-256, Restic's SHA-256 and scrypt profile, npm's SHA-512 integrity metadata, and Tailscale's
provider-managed WireGuard BLAKE2s profile remain tied to the dependency and cryptographic
inventories. Application security values use the operating-system CSPRNG; the application selects
no hash-based random-bit generator.

## Compatibility-only SHA-1

SHA-1 is not an approved general-purpose hash. Exactly six operations retain it for two narrow,
reviewed formats:

- Four HMAC-SHA-1 operations implement or rehearse RFC 6238 TOTP interoperability: one application
  implementation, two release-security helpers, and one browser-test helper. Each account receives
  an independent 160-bit random seed, and the application also enforces short steps, limited clock
  drift, and replay prevention.
- Two direct SHA-1 operations support exact membership in the local breached-password corpus. They
  use the complete 160-bit uppercase digest only as a format-compatible lookup key and explicitly
  pass `usedforsecurity=False`.

These exceptions do not authorize SHA-1 for password storage, signatures, content integrity,
collision resistance, key derivation, random generation, or a new protocol. Removing the TOTP or
corpus compatibility dependency requires removing the matching exception and operation inventory in
the same change.

MD5 is prohibited for every cryptographic purpose. The sole occurrence is Django's fast
`MD5PasswordHasher` in `config.settings.test`, isolated to synthetic in-memory unit tests and
prohibited from hardened, production, pentest, browser, maintenance, and release-candidate targets.

## Change and review procedure

1. Run `python scripts/check_hash_function_policy.py` and the complete quality gate.
2. Review every discovered operation against its stated purpose. Unkeyed hashes must not be treated
   as authentication, and passwords or human-memorable secrets must use the dedicated password
   hashing policy.
3. For a proposed function or new use, document its strength, purpose, prohibited uses, owner, and
   evidence before changing source. Update the cryptographic inventory when the runtime or
   deployment algorithm set changes.
4. Revalidate the pinned Django and cryptography behavior, npm integrity handling, Restic format,
   Tailscale/WireGuard provider profile, and operating-system randomness boundary when their
   dependencies change.
5. Review both SHA-1 exceptions for removal. Compatibility is a bounded exception, not a precedent
   for another weak-hash use.
6. Record the review date and a next-review date no more than 90 days later. Review sooner for every
   release candidate, dependency algorithm change, cryptographic finding, or new hash call.

The repository policy proves source selection and pinned managed defaults. Live provider and release
evidence remains governed by the cryptographic inventory and release process; no key, seed, password,
private hostname, or unrestricted security output belongs in this policy.
