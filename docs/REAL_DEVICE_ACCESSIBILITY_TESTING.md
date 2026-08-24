# Real-device and assistive-technology testing

Status: repeatable evidence system implemented; manual runs pending  
Last updated: 2026-08-24

## Purpose and release boundary

This runbook covers the branded desktop browsers, real or hosted mobile browsers, keyboard,
screen-reader, and zoom checks that engine automation cannot certify. The required targets and
scenario applicability are fixed in `docs/device-test-matrix.json`. A Playwright pass is useful
baseline evidence, but it never substitutes for a target in this matrix.

Only test a clean release-candidate commit on a disposable deployment containing synthetic data.
The mobile test endpoint must use the same private HTTPS and security-header boundary intended for
deployment. Never expose the disposable instance directly to the public internet, weaken cookies or
MFA for convenience, copy household data into it, or connect a manual device to the production
database or volumes.

## Evidence protection and privacy

Manual evidence is intentionally small and reviewable. Keep one JSON record per target under
`docs/device-test-runs/`, submit it through a pull request, and preserve accepted records instead of
rewriting them. The validator binds a run to the full Git commit, exact browser and platform
versions, a date, a non-personal tester role, and every scenario required for that target. Git
history and reviewed, preferably signed release tags provide the provenance trail; the repository
files alone are not a substitute for protected Git hosting and branch controls.

Do not commit screenshots, screen recordings, accessibility speech logs, cookies, passwords, MFA
seeds, device names or identifiers, IP addresses, internal hostnames, transaction details, or raw
developer-tool exports. Record only pass/fail/blocked state and a sanitized observation. Store any
necessary sensitive artifact in the encrypted assessment location described by the release owner,
then reference a non-sensitive finding ID such as `M10-F004`.

## Prepare a run

1. Select and freeze the candidate commit. Set `release_candidate` in
   `docs/device-test-matrix.json` to its 40-character Git SHA.
2. Deploy that exact commit to the isolated synthetic test environment and verify private HTTPS.
3. Seed only disposable accounts, MFA, schedules, transactions, debts, and goals. Confirm the test
   database and volumes are not shared with another environment.
4. Update the browser and operating system when the target says `current`. Use a hosted browser lab
   or a controlled older image for `previous major`; do not downgrade a daily-use browser profile.
5. Use a fresh browser profile or private window, decline credential storage, and clear the
   disposable profile after the run.
6. Record exact version numbers from the browser and platform About screens without recording a
   device serial number or account identity.

## Scenario procedure

- `AUTH-01`: sign in with the disposable password and current MFA code; confirm invalid input has a
  useful, non-secret error; sign out; and confirm protected routes require authentication again.
- `NAV-01`: use every available primary destination, browser Back and Forward, Alerts, and the
  period selector. The active page, page heading, and URL must remain consistent.
- `PERIOD-01`: confirm each period begins at one synthetic paycheck arrival and ends immediately
  before the next. Move an occurrence to an adjacent period and confirm no Sunday-to-Sunday
  assumption appears.
- `BUDGET-01`: review the generated budget, make a period-only income adjustment, and attempt a
  category deletion. No deletion occurs before the explicit reason and confirmation step.
- `SPEND-01`: add a synthetic expense and confirm category, pay-period total, and dashboard
  available-spending value update once without duplicate submission.
- `DEBT-01`: review a synthetic debt and compare minimum, snowball, avalanche, and custom payoff
  projections. Amounts and ordering must remain readable and internally consistent.
- `GOAL-01`: review saving, debt, and investing goal progress. Meaning must not depend on color
  alone.
- `THEME-01`: confirm the first fresh visit is dark, switch to light, navigate and refresh, then
  confirm legibility and the retained preference. Only the theme preference may use local storage.
- `RESPONSIVE-01`: test portrait and landscape, browser text sizing, tables, dialogs, the on-screen
  keyboard, and the bottom navigation. No essential control may be clipped or require two-axis page
  scrolling; primary touch targets must be at least 44 CSS pixels high or wide.
- `SESSION-01`: after sign-out, Back and page refresh must not reveal a protected page. Do not accept
  a browser password-save prompt. Clear the disposable profile when finished.
- `KEYBOARD-01`: without a mouse, use the skip link, Tab, Shift+Tab, Enter, Space, arrows, Escape,
  and form controls. Focus must be visible and logical, disabled placeholders must not act, and no
  component may trap focus.
- `SCREENREADER-01`: with Narrator, VoiceOver, or TalkBack, navigate by headings and landmarks;
  verify link/button names, current/pressed/disabled state, currency totals, table relationships,
  labels, required state, and error recovery. Ensure status changes are announced without reading
  secrets aloud into a recording.
- `ZOOM-01`: at 200 percent browser zoom, all content and controls remain usable. At 400 percent
  (or an equivalent 320-CSS-pixel reflow viewport), content reflows without loss of information or
  two-dimensional page scrolling except for data tables that require it.

Any security, authorization, data-integrity, inaccessible blocking workflow, crash, or data-loss
finding fails the run. Cosmetic issues may be recorded as a finding but still require explicit
release-owner disposition.

## Record and validate a run

Create `docs/device-test-runs/YYYY-MM-DD-target-shortsha.json` with this shape:

```json
{
  "schema_version": 1,
  "run_id": "2026-08-24-keyboard-edge-current-0123456",
  "target_id": "keyboard-edge-current",
  "purpose": "release_candidate",
  "tested_at": "2026-08-24",
  "candidate_commit": "REPLACE_WITH_FULL_LOWERCASE_GIT_SHA",
  "tester_role": "release owner",
  "browser_version": "major.minor.build.patch",
  "platform_version": "product and version only",
  "synthetic_data_only": true,
  "overall_status": "passed",
  "scenario_results": [
    {"id": "KEYBOARD-01", "status": "passed", "notes": "No finding."}
  ],
  "supersedes": null
}
```

Replace the uppercase placeholder with the candidate's full 40-character lowercase Git SHA; the
placeholder is deliberately not valid evidence.

Allowed scenario states are `passed`, `failed`, `blocked`, and `not_run`; the overall state is
derived as `passed`, `failed`, `blocked`, or `partial`. A passed release-candidate record must match
the matrix candidate SHA and pass every applicable scenario. Development baselines can use
`development_baseline`, but they cannot satisfy a release gate. If the same target must be repeated
on the same day and commit, append `-r2` (then `-r3`) to the new run ID and set `supersedes` to the
prior run ID.

Run `python scripts/check_device_test_evidence.py` or the full `scripts/check.ps1` /
`scripts/check.sh` gate while collecting evidence. Before approval, run
`python scripts/check_device_test_evidence.py --require-complete`. Do not mark security test 22 or
release gate 6 verified until that command passes and all related findings are closed.
