# Adversarial-test run records

Keep one sanitized JSON file per manual adversarial target run in this directory. Never edit,
replace, or delete an accepted record; add a later record whose `supersedes` field points to it so
the reviewed Git history remains available.

Do not store raw requests, responses, attack strings, cookies, passwords, MFA material, hostnames,
IP addresses, device identifiers, database output, screenshots, real household data, synthetic
financial values, or reusable infrastructure details here. Raw assessment material belongs only in
the ignored `security-reports/` directory or an encrypted location outside the repository and must
be deleted when the review no longer needs it.

The required fields, scenario procedures, status rules, and execution workflow are defined in
`docs/ADVERSARIAL_TESTING.md`. `scripts/check_adversarial_test_evidence.py` validates every JSON
record and binds failed results to entries in `docs/SECURITY_FINDINGS.md`. This README intentionally
is not test evidence, and the empty directory does not imply a pass.
