# Session security policy

Status: implemented; release-candidate verification pending  
Last reviewed: 2026-09-17

## Scope and assurance target

The private Household Budget application treats an authenticated session as an AAL2-style session
because normal sign-in requires a password and a confirmed TOTP or single-use recovery code. This
is a product risk target, not a claim that the application or deployment has been formally assessed
for NIST conformance. Sessions protect private household identity, income, spending, debt, reserve,
goal, and audit data, so unattended and long-lived browser access is deliberately bounded.

## Enforced limits

| Boundary | Production limit | Enforcement and rationale |
| --- | ---: | --- |
| Inactivity | 1 hour | `SESSION_IDLE_TIMEOUT_SECONDS`; a request after the limit terminates the server session and requires the full password-plus-MFA login flow. This matches the NIST AAL2 recommended maximum. |
| Overall lifetime | 12 hours | `SESSION_ABSOLUTE_TIMEOUT_SECONDS` and `SESSION_COOKIE_AGE`; this is stricter than the NIST AAL2 recommended maximum of 24 hours because the application exposes consolidated financial data. Successful sensitive-action reauthentication does not extend this limit. |
| Activity persistence | 60 seconds | `SESSION_ACTIVITY_UPDATE_SECONDS`; active requests refresh the stored last-seen time at most once per minute to limit database writes without relaxing the 1-hour inactivity decision. |
| Sensitive-action freshness | 10 minutes | `RECENT_AUTH_TIMEOUT_SECONDS`; password changes, session revocation, all-device logout, protected exports, and other guarded actions require a fresh password plus TOTP or recovery-code verification. This is an additional control and does not extend the overall session lifetime. |
| Concurrent sessions | 5 | `MAX_CONCURRENT_SESSIONS`; after a sixth fully authenticated session is saved, the oldest active session for that account is deleted while the new session is preserved. Per-account enforcement is serialized with a database lock. |
| Browser persistence | Browser session only | Hardened settings enable `SESSION_EXPIRE_AT_BROWSER_CLOSE` and use a host-only, path-rooted, Secure, HttpOnly, SameSite=Strict session cookie. There is no remember-me mode. |

Session version changes, user disablement, administrator revocation, explicit logout, current-session
revocation, inactivity, and overall expiry all invalidate server-side authentication. Secure
termination responses direct the browser to clear its cache, cookies, and origin storage; logout
forms also clear supported client storage and authenticated DOM content without waiting for the
server.

Disabling an existing account synchronously removes all of its stored authenticated and pending-MFA
sessions. Deleting an account does the same for both individual and queryset deletion paths. A
browser that later presents one of the displaced cookies is redirected to full login and receives
the secure client-state cleanup response. Both lifecycle events are recorded in the security log.

The concurrent limit counts only unexpired, current-version authenticated sessions; incomplete MFA
attempts and stale session versions do not consume a slot. A new valid password-plus-MFA login is
not rejected at the limit. Instead, the oldest authenticated session is revoked deterministically,
the replacement login succeeds, and the security stream records the automatic revocation. The
evicted browser is redirected to full login and receives the client-state cleanup response on its
next request. Users can review and individually revoke the remaining sessions from Account
security, or revoke all of them after recent reauthentication.

## Administration and upgrade boundary

Django administration uses the application's password-plus-MFA login, never Django's default
password-only form. Every protected admin view requires an active staff account, completed MFA
enrollment, explicit MFA proof in the current server-side session, and authentication within the
10-minute freshness window. Enrollment state alone is not session proof. Missing proof or stale
authentication redirects staff to the full password-plus-TOTP/recovery-code reauthentication flow;
non-staff users are denied. Internal session versions and authentication timestamps are read-only
in the user editor. Admin CSRF protection and no-store response policy remain enabled.

Staff browser accounts must have an active household membership for the application authentication
flows. Initial enrollment and session-security reinitialization do not manufacture MFA proof;
administration requires reauthentication when that proof is absent.

When deploying the fix for `M10-F024`, revoke all pre-upgrade authenticated and pending-MFA sessions
from the trusted maintenance environment before restoring user traffic:

```text
python manage.py revoke_user_sessions --all-users --reason "M10-F024 session boundary upgrade" --confirm revoke-all-sessions
```

Use the release's configured production settings and maintenance identity. The admin gate rejects
legacy sessions without proof, but ordinary application session handling does not distinguish all
historical password-only sessions. The revocation step is therefore required, not optional. Retain
sanitized release evidence that old cookies fail and fresh password-plus-MFA sign-in succeeds.
Repository regression tests are not evidence that this production operation has been executed.

## Standards decision

NIST SP 800-63B section 2.2.3 recommends no more than 24 hours overall and no more than 1 hour of
inactivity for AAL2 reauthentication. The product uses the recommended inactivity ceiling and a
tighter 12-hour overall limit. There is therefore no timeout deviation that weakens the NIST AAL2
recommendation. The stricter overall limit is retained because a stolen unattended session exposes
highly aggregated financial data and the private deployment has no device-bound session credential.

Any change that lengthens either limit requires a documented threat assessment, an explicit NIST
comparison, updates to the source settings and this policy, focused timeout tests, the full quality
gate, and release-candidate verification. The current reference is
<https://pages.nist.gov/800-63-4/sp800-63b/aal/#aal2reauth>.
