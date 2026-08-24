# Browser security and compatibility testing

Status: automated baseline and manual evidence system implemented; manual passes remain separate
Last updated: 2026-08-24

## Purpose and safety boundary

This suite exercises the real password-and-TOTP sign-in path, authenticated workflows, browser
security controls, accessibility, and responsive layouts in Chromium, Firefox, and WebKit. It runs
only against the disposable synthetic PostgreSQL profile in `compose.pentest.yaml`. The Playwright
configuration rejects any base URL other than `http://pentest-web:8000`, and every attached Docker
network is internal.

Never redirect this suite to a deployed application or populate it with household data. It creates
expenses and a temporary category budget. Its fixed Compose project is destroyed with its database,
media, credentials, MFA seed, cookies, and browser state after every run, including a failed run.
Screenshots, traces, videos, and HTML reports are disabled because they can retain authenticated or
financial test data.

## Run locally

Docker with Compose is the only runtime prerequisite; Node.js and browsers do not need to be
installed on the host.

```powershell
.\scripts\run-browser-tests.ps1
```

From Linux or WSL:

```sh
sh scripts/run-browser-tests.sh
```

The runner first removes any stale `budgetapp-browser` project, builds the production-derived
synthetic app and the digest-pinned Playwright image, waits for a healthy app, runs the tests once,
and always removes containers, networks, and volumes. Do not reuse the `budgetapp-pentest` project
or normal application volumes for browser testing.

## Automated matrix

| Project | Engine | Viewport and interaction |
|---|---|---|
| chromium-desktop | Chromium | 1440×900 desktop |
| firefox-desktop | Firefox | 1440×900 desktop |
| webkit-desktop | WebKit | 1440×900 desktop |
| chromium-phone | Chromium | 390×844, touch/mobile |
| firefox-narrow | Firefox | 390×844 responsive layout |
| webkit-iphone | WebKit | 390×844, touch/mobile |
| webkit-ipad | WebKit | 1024×1366, touch/mobile |

A Chromium setup project signs in through the rendered forms using the disposable Alex password and
current TOTP code. A networkless one-shot service first copies only Alex's password and TOTP seed
into a browser-scoped volume owned by the non-root browser account; the test container never mounts
the full pentest secret or authentication volumes. It writes one mode-0400 storage-state file under container `/tmp`; all projects
reuse that short-lived session to avoid TOTP replay and authentication-throttle interference.

Every engine/viewport checks navigation, dark-mode default and light-mode persistence, horizontal
overflow, protected workflows, browser storage, uncaught JavaScript errors, and manual expense
entry. The suite also checks cookie and response headers, CSP-backed reflected/fragment DOM-XSS
inertness, WCAG 2 A/AA rules with axe-core on key pages, and the explicit reason-plus-checkbox
confirmation required to delete a category budget. Desktop engines also verify the keyboard skip
path, logical initial focus order, visible focus ring, theme activation, and inert unavailable
navigation. Phone, narrow, and iPad layouts measure their exposed primary navigation targets
against the 44-CSS-pixel minimum.

## CI and dependency controls

`.github/workflows/browser.yml` runs on pull requests and manual dispatch. It has read-only contents
permission, does not persist checkout credentials, and invokes the same disposable runner. It is
separate from the normal quality job because the multi-engine image is large and the browser suite
is intentionally serialized for deterministic shared-database writes.

The Playwright npm package and Microsoft browser image use the same exact version. The image and
GitHub action are pinned to immutable digests/commits, `npm ci` ignores lifecycle scripts, and the
build fails on high-severity npm audit findings. Dependabot reviews npm changes independently.

## What automation does not prove

Playwright's WebKit is not branded Safari, a narrow Firefox engine is not Firefox for iOS or Android,
and automated axe rules detect only part of accessibility problems. Before release, complete manual
keyboard/screen-reader review and smoke tests on available real or hosted iPhone/iPad Safari and
Firefox plus Android Chrome and Firefox. Edge and branded current/previous Chrome/Firefox version
support also requires release-candidate coverage beyond these engine baselines. The exact matrix,
safety boundary, procedures, and sanitized evidence format are defined in
`docs/REAL_DEVICE_ACCESSIBILITY_TESTING.md`; pending runs remain pending rather than inheriting an
automated engine result.
