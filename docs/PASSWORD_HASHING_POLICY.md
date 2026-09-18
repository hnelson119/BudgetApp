# Password hashing policy

Status: implemented boundary; release performance verification pending
Last reviewed: 2026-09-13
Next review due: 2026-12-12

## Production rule

Every stored account password uses Django 5.2.17's `PBKDF2PasswordHasher`, encoded as
`pbkdf2_sha256` with HMAC-SHA-256, 1,000,000 iterations, and an independently generated salt with a
128-bit entropy target. `config/settings/base.py` explicitly selects that single production hasher;
production, hardened, pentest, integrity, and maintenance settings inherit it.

Application code never assigns a password field directly. Account creation, authenticated password
change, forgotten-password recovery, and the emergency console reset all call Django's
`set_password`. Verification uses `User.check_password` or Django's constant-time `check_password`
helper. Stored encodings contain the algorithm identifier, work factor, salt, and derived output,
not the candidate password.

MFA recovery codes use the same one-way password-hashing interface. Dummy hashes for absent or
already-consumed recovery records keep those paths from turning into a simple record-existence
timing signal. Those uses remain separate from account passwords in the machine inventory.

## Selection and performance rationale

The algorithm and work factor are the reviewed default in the repository's exact Django 5.2.17
dependency. PBKDF2-HMAC-SHA-256 is deliberately slow, salted per value, and supported by Django's
upgrade machinery. The private deployment has only two human users, so a one-million-iteration
login cost is acceptable when combined with the keyed identifier/network throttle. The throttle
blocks repeated failures after five attempts in a 15-minute window, limiting online guessing while
the password hash raises offline attack cost.

For each release host, benchmark one encode and three correct/incorrect checks with synthetic
values. Record the median and slowest result as sanitized release evidence. A normal hash should
remain usable for an interactive login while being intentionally expensive; investigate results
below 200 ms or above 1,000 ms. Do not weaken the work factor merely to make a test pass. If the
upper bound is exceeded, first verify CPU allocation and host contention, then select and review a
new approved configuration with migration evidence.

## Test-only exception

`config.settings.test` replaces the hasher list with Django's MD5 test hasher so hundreds of
synthetic unit-test credentials do not consume the production work factor. This exception is valid
only for in-memory local tests. Production, hardened, pentest, browser, migration, backup, restore,
or release-candidate settings must never import or select it, and no security-strength claim may be
based on a hash created under test settings.

## Upgrade and recovery

An algorithm, dependency, or work-factor change requires a cryptographic inventory review, a
representative performance measurement, authentication and recovery regression tests, and a plan
for existing encodings. If an approved replacement is introduced, place it first and retain the
previous approved hasher only as a temporary verification fallback until successful logins or an
explicit offline migration rehash every active credential. Never remove the old verifier while
valid hashes still use it, and never rehash without first verifying the candidate.

A suspected password-hash weakness triggers forced password reset, session revocation, incident
review, and a new release. Changing the hasher alone does not invalidate stolen old hashes. Encrypted
backups retain prior encodings until their documented expiry and must be included in containment.

## Enforcement

`docs/password-hashing-policy.json` is the authoritative machine inventory. Its checker pins the
production and test setting assignments, the dependency version, primitive parameters, and all 14
current password-hash or verification operations across six production files. A new call site,
direct password assignment, renamed hasher helper, algorithm or iteration drift, missing evidence,
or stale review fails both quality gates.

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_password_hashing_policy.py
.\.venv\Scripts\python.exe -m pytest tests\test_password_hashing_policy.py
```

The release candidate still needs a dated performance result and a sanitized stored-format check
from the selected host before this implemented control can be marked verified.
