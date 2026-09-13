# Input validation policy

Status: implemented policy; release verification pending
Last reviewed: 2026-09-13
Next review due: 2026-12-12

## Purpose

This policy defines the structure, cross-field consistency, and business limits of every current
user-input family. It implements the documentation requirements in OWASP ASVS 5.0.0
`v5.0.0-2.1.1`, `v5.0.0-2.1.2`, and `v5.0.0-2.1.3`. The machine-readable source is
`docs/input-validation-policy.json`; the normal local and CI gates validate it with
`scripts/check_input_validation_policy.py`.

The catalog covers all 49 form classes in the eight production form modules. Abstract household
form bases are included because they establish the scoping contract inherited by concrete forms.
Commands, middleware, and service-only inputs are represented by the rule and source-assertion
catalogs even when they do not use a Django form.

## Required order

Every untrusted value follows one server-controlled sequence:

1. Decode the transport representation exactly once into its canonical value.
2. Validate type, syntax, length, range, precision, and allowed values.
3. Resolve identifiers only through the active household or another purpose-scoped queryset.
4. Validate cross-field, referenced-object, lifecycle, accounting, and recurrence consistency.
5. Apply resource and business limits before expensive work or durable state changes.
6. Repeat security-critical invariants in transactional services and database constraints.

Browser attributes improve usability but are never the authoritative validation boundary. A view
may act only on a valid form, and a domain service rechecks invariants that could be bypassed by a
different caller or invalidated by concurrent state changes. Failure leaves no partial durable
change. Validation responses identify the field or safe corrective action without reflecting
secrets, raw upload contents, internal object identifiers, or exception details.

## Structure rules

The catalog defines ten input families: authentication, MFA, financial values, bounded text,
calendar recurrence, opaque identifiers, scoped object references, CSV content, enumerated
controls, and local action targets. Their central contracts are:

- Money is finite `Decimal(18,2)` and rates are finite `Decimal(7,4)` values from 0 through
  999.9999 percent. Each operation separately chooses positive, nonnegative, or signed semantics.
- Names, descriptions, notes, reasons, references, and searches have purpose-specific length
  limits. Passwords preserve whitespace; security-relevant labels and reasons are normalized in
  their service boundary.
- Dates and times become typed values before use. Recurrence components use fixed enums and valid
  calendar ranges rather than free-form expressions.
- UUIDs and action references are parsed before lookup. Submitted object identifiers resolve only
  through a queryset already restricted by household, type, and lifecycle state.
- CSV is the only upload family. It requires bounded strict UTF-8 text with a valid, unique header
  and bounded rows, columns, and cells; archives and active content are not accepted.

## Combined and contextual rules

Ten rule groups define combinations that scalar field validation cannot establish. They require
one active household across all related objects; frequency-compatible recurrence components;
consistent goal source, destination, and debt relationships; ordered immutable debt terms and
statements; reconciled mortgage components; balanced double-entry postings; valid reversal,
refund, and reconciliation state; distinct CSV mapping columns and current staging tokens; MFA
credential, user, version, and session agreement; and one ordered household audit chain.

These checks occur as close as practical to the atomic state transition. Dynamic form querysets
provide an early rejection and clearer error, while the transactional service locks and reloads
authoritative records before it decides.

## Business limits

The eleven cataloged limit groups pin the current values and their enforcement sources. Notable
limits include 5 MiB/10,000 rows/50 columns/1,000 characters for CSV; one-hour idle and twelve-hour
absolute sessions; five concurrent sessions; five login failures within fifteen minutes; a
30-second TOTP period with one step of drift; a 25-year and 10,000-result recurrence-preview cap;
five-year synchronization windows; 100 debts and 1,200 months per payoff projection; 0-30 day
notification windows; and 50 records per transaction or audit page.

Changing a limit requires a single review that updates the source, tests, machine-readable policy,
capacity and abuse rationale, and any user-facing help text. The checker deliberately fails when a
source constant, paginator, form registry, evidence path, review date, or catalog count drifts.

## Ownership and review

The application maintainer owns this policy. Review is required at least every 90 days and whenever
a form module, accepted input type, upload format, domain state transition, resource-intensive
operation, authentication factor, persistence model, or externally reachable route changes. New
input cannot ship until its structure, combinations, business limits, failure behavior, and test
evidence are classified here.

This is implementation evidence, not a release pass. ASVS `v5.0.0-2.3.2` remains partial because
the catalog does not itself prove an exhaustive independent review that every business rule is
enforced at every applicable trust boundary. The three implemented policy requirements also need a
dated release-candidate adversarial run and sanitized retained evidence before they can be marked
verified.
