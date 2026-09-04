# Offline password blocklist

Status: implemented; release-candidate verification pending
Last updated: 2026-09-04

## Policy and privacy boundary

Every new or changed application password is checked through Django's configured password
validators. This includes trusted-console household provisioning and emergency password reset,
self-service password change, and forgotten-password recovery. Low-level `UserManager.create_user`
calls retain Django's normal separation of concerns and do not independently apply password policy.

The checks are entirely local. The application never sends a candidate password, full digest,
digest prefix, or other password-derived value over a network. The breached-password validator
computes an uppercase SHA-1 digest in process only because the reviewed offline corpus uses the
HIBP-compatible SHA-1 representation. This lookup digest is not logged, retained, or used as the
application's password-storage algorithm.

Production and penetration-test settings validate the packaged corpus while settings load. They
fail closed if it is missing, unsafe, corrupt, too small, too large, internally inconsistent,
future-dated, or more than 180 days past its recorded source-retrieval date.

## Context-specific prohibited words

The authoritative identifiers in `config/settings/base.py` are:

- `BudgetApp`
- `Household Budget`
- `Paycheck Budget`

The validator applies Unicode NFKC normalization and case folding, removes separators, and maps
the common substitutions `@→a`, `$→s`, `0→o`, `1→i`, `3→e`, `4→a`, `5→s`, and `7→t`. It rejects
each normalized identifier by itself and with any one optional prefix (`my`, `our`, `the`), any one
optional suffix (`app`, `home`, `admin`, `password`), and a trailing zero-to-four-digit numeric
suffix. Both substitution and literal-numeric interpretations of trailing digits are tested so a
numeric suffix does not create a leetspeak bypass.

Examples of prohibited forms include `BudgetApp`, `my-budget-app2026`, `Budg3t@pp42`, and
`our household budget admin 7`. These examples are documentation, not usable credentials. Any
identifier or permutation change must update the setting, this list, and focused policy tests in
the same reviewed change.

## Packaged corpus and strict format

The immutable image includes `identity/data/breached-passwords-v1.txt`. The version-1 format is:

1. The exact `HOUSEHOLD-BUDGET-BREACHED-PASSWORDS-V1` magic record.
2. One UTF-8 JSON metadata record with exactly the required fields.
3. Fixed-width records containing unique, uppercase, lexicographically sorted 40-character SHA-1
   digests, one per line.

The metadata records the format version, entry count, generation and retrieval dates, selection
method, source name and HTTPS URL, SHA-256 of the reviewed local source, and SHA-256 of the hash
payload. Loading also requires a regular non-symlink file, a matching open-file identity, a
25 MiB maximum, exact fixed-width payload length, and no group/world write bit on POSIX. The
current minimum is 10,000 records. Binary search operates directly on the fixed-width bytes, so no
large in-memory set or writable runtime index is needed.

The baseline corpus was generated on 2026-09-02 from the first 10,000 source-order entries in the
NCSC `PwnedPasswordsTop100k` list preserved by OpenXPKI at immutable commit
`5c0389789c6275095aec7d6db2dbd85cd5869405`. That preserved module attributes the list to the NCSC
publication derived from Troy Hunt/HIBP data. The transient decoded source had SHA-256
`4d51ef5bc21a2b5e3f219f51e8e1c2ef3506e47e0efb981d5e08f7ade1b2ca3c`; the selected hash payload
has SHA-256 `53f0173e5af723212c19635c7df63647affedcd41bf25a8c62ee3af6e4b6217e`.
The complete packaged file has SHA-256
`92873cd5159a599d022792393a3a76b887da41cbbf09b4ef544b3e1386fa4627`. The corpus metadata is the
authoritative machine-readable provenance record.

## Reviewed update procedure

Corpus updates are maintainer operations. The running application does not download data. Prefer a
current SHA-1 `HASH:COUNT` corpus acquired with the official Have I Been Pwned
`PwnedPasswordsDownloader` from its official repository. Review the downloader release and source,
retrieve into an encrypted temporary location outside this checkout, record the retrieval date and
provenance URL, and compute the complete local file's SHA-256 before transformation. The digest
proves that the reviewed input and transformed input are identical; it does not replace source
authenticity review.

Build a bounded corpus from the reviewed local HIBP file:

```powershell
python manage.py build_breached_password_corpus `
  D:\reviewed-input\pwned-passwords-sha1.txt `
  identity\data\breached-passwords-v1.txt `
  --input-format hibp-sha1 `
  --expected-sha256 <64-lowercase-hex-digest> `
  --source-name "Have I Been Pwned Pwned Passwords" `
  --source-url "https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader" `
  --source-retrieved-at YYYY-MM-DD `
  --max-entries 100000 `
  --minimum-entries 10000 `
  --replace
```

`hibp-sha1` selects the highest breach counts; equal counts use the lower digest first so the
result is deterministic regardless of source order. `plaintext` is supported only for a reviewed
UTF-8 list and selects the first source-order entries. It hashes them immediately and writes no
plaintext to the output. Both modes read the entire bounded-line source to verify its SHA-256.

After building:

1. Review the metadata, source and payload digests, dates, entry count, and corpus-only diff. Update
   the exact whole-file digest allowlist in `scripts/secret_scan.py`; it prevents the hash records
   from creating generic high-entropy false positives while refusing any unreviewed file change.
   Never stage the transient source.
2. Run `python -m pytest tests/test_password_policy.py`, the complete `scripts/check.ps1` or
   `scripts/check.sh`, and the production settings/deployment checks.
3. Build the production image and confirm the corpus exists with non-writable runtime permissions.
4. Deploy the reviewed image and restart every web, migration, maintenance, recovery, and security
   test process that can set passwords. Processes cache the validated immutable corpus.
5. Retain the prior reviewed image for rollback. Roll back only to a corpus that still passes the
   size, integrity, and 180-day freshness policy; never disable the validator or lower a bound to
   recover service.

Delete transient source files after review and transformation. Ordinary deletion is not a reliable
secure erase on SSDs or copy-on-write storage, so use encrypted temporary storage from the start,
avoid synchronized folders and backups, remove the file through the operating system, and destroy
the temporary encryption key or volume according to the host procedure. Never commit plaintext
password lists or full downloaded source corpora.

## Verification expectations

Unit and integration tests cover normalized context variants, known breached/non-breached values,
strict metadata and payload failures, stale/future dates, symlinks and POSIX permissions, builder
input modes and deterministic ties, source-digest and replacement guards, atomic failure cleanup,
no network call, and no candidate/digest log output. These are repeatable implementation evidence,
not a completed independent penetration test or release-candidate verification.

Primary references:

- NIST SP 800-63B, password blocklists: <https://pages.nist.gov/800-63-4/sp800-63b.html>
- OWASP Authentication Cheat Sheet: <https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html>
- HIBP API/corpus format: <https://haveibeenpwned.com/API/v3>
- Official HIBP downloader: <https://github.com/HaveIBeenPwned/PwnedPasswordsDownloader>
- Django password validation: <https://docs.djangoproject.com/en/5.2/topics/auth/passwords/>
