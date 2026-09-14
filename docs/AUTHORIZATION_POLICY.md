# Authorization policy

Status: implemented policy; release verification pending
Last reviewed: 2026-09-13
Next review due: 2026-12-12

## Purpose and decision model

This policy implements OWASP ASVS 5.0.0 `v5.0.0-8.1.1` and `v5.0.0-8.1.2` by defining
function-, record-, and field-level authorization for the current private household application.
The machine-readable source is `docs/authorization-policy.json`; the normal local and CI gates run
`scripts/check_authorization_policy.py`.

Authorization is server-side and deny by default. Passing authentication, knowing a UUID, seeing a
link, submitting a hidden field, or belonging to some other household grants no authority. The
authoritative decision combines consumer state with resource attributes: active membership,
selected household, record ownership, recipient, lifecycle status, account classification, recent
authentication, integrity state, and operation purpose.

## Consumer states

There are four policy states:

- Anonymous consumers receive only minimal liveness, login, and generic password recovery.
- A password-accepted pending-MFA session may only complete its bound, expiring MFA challenge; it
  is not an authenticated household session.
- An authenticated user with an active `HouseholdMembership` is an active household member.
  Members have equal application access inside the selected household; the initial product has no
  owner, editor, or read-only household subroles.
- A trusted administrator uses separately authorized host access, reviewed management commands, or
  Django staff permissions. Administrator capability is not implied by household membership.

An authenticated user without exactly one resolvable active household is denied rather than given
an arbitrary household. If multiple-household selection is expanded, the selected reference must
still resolve through that user's active memberships.

## Function- and record-level rules

The route matrix classifies all 70 named routes across nine application namespaces. The checker
discovers those routes from source, requires every named route to appear exactly once, verifies the
login guard on member and recent-auth routes, and verifies the fresh-auth check on the five routes
classified as sensitive.

Ordinary financial functions use equal active-member access and then restrict records by the
selected household. Services repeat membership and relationship checks inside atomic operations,
so calling them outside the normal view does not bypass ownership. Status and type attributes
further constrain edits: closed periods, archived categories or accounts, reversed entries,
immutable revisions, stale previews, foreign accounts, and inconsistent debt or goal relationships
remain unauthorized or invalid even for a member.

Notifications add a narrower recipient attribute. A member may refresh household evaluation and
edit their own preference record, but only the recorded recipient may list, read, or dismiss a
notification. Imports are household-scoped rather than uploader-private; any active member of the
selected household may review and complete its staged batch, subject to current state and the
confirmation token.

Audit history is readable by active household members. Transaction and audit CSV exports require
recent password-plus-MFA proof, and audit export also requires a valid chain. Password changes,
individual session revocation, and all-device revocation require the same recent-auth elevation.
The application exposes no generic record API or generic model serializer.

## Field-level rules

Forms and explicit serializers are allowlists. Household foreign keys, primary keys, ownership,
creator fields, timestamps, hashes, key versions, counters, posting sides, entry relationships,
idempotency values, revision sequence, notification recipient, audit chain fields, and maintenance
results are service-managed rather than client-assignable.

Credential material is the strictest case. Password hashes, encrypted TOTP secrets, recovery-code
hashes, session payloads, and CSRF secrets are not household-readable. Raw recovery codes are shown
only during the bound enrollment flow and are then retained only as one-way hashes. A member may
change their own password but cannot directly write email, staff flags, MFA state, session version,
or last-authenticated metadata.

Financial pages may display the selected household's purpose-approved fields. Mutations expose
only the business inputs for that action; balanced postings, revisions, corrections, derived
balances, import fingerprints, and protected audit events are computed by services. Corrections
append history rather than granting write access to prior accounting or audit fields.

Templates and transaction/audit CSV writers explicitly select fields after household and
sensitivity checks. Operational logging is a separate minimized representation and excludes
emails, names, financial contents, request bodies, query values, secrets, and raw object
identifiers.

## Failure, ownership, and change control

Unauthenticated browser access redirects to login where appropriate. Authenticated foreign-object
lookups use concealed not-found behavior or permission denial, and the response boundary records a
redacted `authorization.denied` event without paths, query strings, route arguments, object IDs, or
exception text. A denial performs no partial durable mutation.

The application maintainer owns this policy. Review is required at least every 90 days and before
adding a route, household role, invitation, membership-management flow, editable identity
attribute, API, serializer, external identity provider, service identity, new data model, or new
administrator operation. Each change must update the route, function, record, and field rules plus
positive and negative tests.

This policy is implementation evidence, not a release pass. A dated release-candidate adversarial
authorization run with sanitized retained evidence is still required before either requirement is
marked verified.
