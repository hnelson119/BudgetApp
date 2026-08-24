# Device-test run records

Keep one sanitized JSON file per manual browser or assistive-technology run in this directory.
Never edit or replace an accepted run record; add a new record that supersedes it so Git history
retains the review trail. Do not store screenshots, passwords, MFA seeds, cookies, financial data,
device identifiers, IP addresses, or raw browser logs here.

The required fields and execution process are defined in
`docs/REAL_DEVICE_ACCESSIBILITY_TESTING.md`. `scripts/check_device_test_evidence.py` validates every
JSON record in this directory. This README intentionally is not test evidence.
