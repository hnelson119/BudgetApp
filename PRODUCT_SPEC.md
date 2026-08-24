# Household Budget Application — Product Specification

Status: Approved planning baseline
Last updated: 2026-08-21
Initial deployment: Private, self-hosted Linux VM in Hyper-V

Security requirements are defined in the companion `SECURITY_PLAN.md`. Where the documents overlap, the stricter security requirement applies.

## 1. Product summary

The application is a private budgeting tool shared by two equal household members. It organizes cash flow around paycheck-to-paycheck periods, tracks planned and actual spending, schedules recurring income and expenses, compares debt payoff strategies, and supports prioritized savings, payoff, and investing goals.

The application is planning-oriented rather than bank-balance-oriented. Manual balances and CSV imports are supported, but bank synchronization is outside the initial release.

## 2. Approved product decisions

- Two separate user accounts share one household and have equal editing permissions.
- The audit trail identifies which household member performed every material action.
- Default theme is dark; light theme is available.
- Currency is USD and the initial household timezone is America/New_York.
- The application is responsive for desktop, iPad, and iPhone, with supported current versions of Chrome, Edge, Firefox, and Safari as applicable to each platform.
- There is no offline mode in the initial release.
- Budget periods are created by paycheck events, not calendar weeks.
- Regular income sources may start a new budget period; bonuses and other one-off income do not by default.
- Bills default to the paycheck period containing their due date and may be moved for one period.
- Income and debt schedules sync one way into generated budget entries.
- Editing a generated entry changes that period only; editing its source schedule changes future periods.
- Spending transactions are manual or imported from CSV.
- Purchases, transfers, debt payments, and goal contributions are distinct transaction types so money is not counted twice.
- Credit-card purchases count against their spending category when purchased; the later card payment is a transfer/debt settlement, not another categorized expense.
- Unassigned surplus remains visibly unallocated and accumulates in a persistent Household Reserve when a period closes.
- Manual accounts and balance snapshots are part of the initial release.
- A mortgage may contain principal, interest, escrow, and other components and may be funded through multiple installments per month.
- The system never silently reduces expenses, goals, or spending plans when income is short.
- Paid/completed periods remain editable, with every change preserved in a protected audit history.
- Initial remote access is private-device access through Tailscale; the app is not exposed to the public internet.

## 3. Product principles

1. **Paycheck first:** Every planning view answers what must happen before the next paycheck.
2. **Planned versus actual:** A schedule is not treated as proof that money was received or paid.
3. **Overrides are local:** One-off changes must not silently rewrite a recurring series.
4. **Surplus stays visible:** Unallocated money never disappears into a generic spending total.
5. **No silent automation:** Boundary shifts, shortfalls, imports, and destructive actions require clear review.
6. **History is accountable:** Material changes are append-only, attributable, and tamper-evident.

## 4. Users and authorization

### Household member

Both members can:

- View and edit all household financial data.
- Manage schedules, categories, goals, debts, imports, and manual balances.
- View and export the household audit history.
- Mark income received and expenses paid.

Neither member can:

- Edit, delete, truncate, or clear audit records.
- access deployment secrets, database credentials, or signing keys through the application.

### Deployment administrator

The person maintaining the VM can deploy updates and restore backups. Operating-system or database superuser access can bypass ordinary database controls, so external audit checkpoints and off-VM backups are required to make such tampering detectable.

## 5. Navigation and screens

Primary navigation:

1. Overview
2. Budget
3. Income
4. Spending
5. Debts
6. Goals
7. Settings

Settings includes Household, Categories, Notifications, Security, Manual Accounts, and Audit History.

## 6. Paycheck-anchored period engine

### 6.1 Anchor income

Each income source has a `starts_budget_period` setting.

- Regular paycheck: on by default.
- Variable side income: off by default.
- One-time bonus: off by default.
- The user may change the setting for any source.

An anchor occurrence has an expected availability date in the household timezone. Future period boundaries are projected from expected occurrences.

### 6.2 Boundary algorithm

1. Generate expected occurrences for every active anchor income source.
2. Sort and combine occurrences by local availability date.
3. Multiple anchor paychecks on the same date create one boundary and one period.
4. A period begins on an anchor date and ends immediately before the next distinct anchor date.
5. Internally the range is half-open: `start_date <= item_date < next_start_date`.
6. The displayed end date is the calendar day before the next boundary.

Example:

- Paycheck available Thursday, August 20.
- Next paycheck available Thursday, August 27.
- Displayed budget period: Thursday, August 20 through Wednesday, August 26.

Periods can therefore be 7, 14, 15, 16, or another number of days when job schedules change.

### 6.3 Early or late paychecks

Future planning uses the expected boundary. If an actual paycheck is recorded on a different date, the application asks whether to:

- Move the boundary to the actual date and preview affected items; or
- Keep the scheduled boundary and record only the actual receipt date.

The application never moves a boundary silently. Closed historical periods never change unless a household member explicitly confirms the change.

### 6.4 Schedule changes

Schedule edits require an effective date.

- Occurrences before the effective date remain unchanged.
- Unmodified future occurrences are regenerated.
- Period-specific overrides remain attached to their chosen period.
- A preview shows created, removed, shortened, lengthened, and merged periods before confirmation.

### 6.5 Period assignment

- Recurring bills and debt payments default to the period containing their due date.
- Income defaults to the period containing its expected availability date.
- A user may move one generated occurrence to another period without modifying the schedule.
- A moved occurrence displays its original and current period in the audit history.

## 7. Recurrence rules

Income, fixed expenses, debt payments, goal contributions, and notifications use a shared recurrence model.

Supported initial patterns:

- One-time date
- Every N days or weeks
- Weekly or biweekly on selected weekdays
- A fixed day of each month
- Every N months, including quarterly schedules
- Nth weekday of a month, such as the second Wednesday
- Last weekday of a month
- Annual date

Rules include a start date, optional end date, household timezone, active state, and effective-dated revisions. The schedule preview must show at least the next three occurrences before saving.

## 8. Source schedules and one-way synchronization

Recurring sources generate independent occurrence records.

### Source edit

Editing an Income, Fixed Expense, Debt, or Goal schedule updates only unmodified future occurrences from the selected effective date.

### Occurrence edit

Editing an occurrence from Budget creates a period-specific override. The source schedule is unchanged. The UI displays source provenance and the message: “Changes here affect this pay period only.”

### Deletion

Recurring items offer:

- Only this occurrence
- This and all future occurrences

Both choices require confirmation. Completed history and audit events remain. Domain records should be archived or cancelled rather than physically deleted when they have financial history.

## 9. Dashboard

The default dashboard opens to the current paycheck period and shows:

- Planned and received income
- Planned fixed expenses and required debt payments
- Scheduled goal contributions
- Variable spending budget
- Spending remaining
- Unallocated excess
- Period status: on track, attention needed, or deficit
- Bills due before the next paycheck
- Goal progress
- Recent spending transactions
- Previous and next paycheck-period controls

The dashboard must not label calculated cash flow as a verified bank balance.

## 10. Budget

The period budget contains grouped Income, Fixed Expenses, Required Debt Payments, Goal Contributions, and Variable Budgets.

Each row supports:

- Planned amount
- Actual amount
- Due/availability date
- Category
- Source provenance
- Status: scheduled, received, upcoming, paid, overdue, moved, overridden, or cancelled
- Notes
- Period-only edit
- Move to another period
- Safe deletion/cancellation

The table supports search, category and status filters, and expandable groups.

## 11. Income

An income source contains:

- Name
- Expected amount or variable amount
- Recurrence rule
- Expected availability date or weekday
- Whether it starts a budget period
- Effective date
- Active/archived state
- Optional notes

Income may be marked received with an actual date and amount. A one-time bonus may be added directly to one period without creating a new schedule or period boundary.

## 12. Spending and categories

### Manual transactions

Required fields are date, description, amount, transaction type, and affected account or accounts. Expenses additionally require a category. Optional fields include note and receipt reference.

Initial transaction types are:

- Income
- Expense/purchase
- Expense refund (append-only correction)
- Account transfer
- Debt payment
- Goal contribution
- Interest or fee
- Balance adjustment

Transfers between household accounts do not count as spending. A credit-card purchase counts against its spending category on the purchase date and increases the card liability. A later payment from checking to the card reduces checking and the card liability without creating a second spending-category expense. Interest and fees remain expenses.

### Variable category budgets

Examples include Groceries, Fuel, Dining, Entertainment, and Household. Category budgets are period-specific planned limits. Categories may be created, renamed, reordered, colored, and archived.

### CSV import

The import workflow includes:

1. Upload
2. Column mapping
3. Preview
4. Duplicate review
5. Category review
6. Confirmation
7. Completion summary

Mappings may be saved per file format. Duplicate detection uses a normalized fingerprint of transaction date, amount, description, and optional account. Nothing is committed until confirmation. The import batch and resulting transactions are audited.

The initial importer creates categorized expenses against one selected account. A configurable sign
rule excludes income, credits, or unlinked card refunds from a statement preview; those transaction
types remain explicit manual workflows until a safe reconciliation/linking design is added.

### CSV export

Transaction export uses the selected paycheck-period or all-history scope and the active search,
type, and account filters. It requires recent password-plus-MFA verification and a valid protected
audit chain. The response is a streamed, non-cacheable attachment; no export file is retained.
Untrusted text that begins with a spreadsheet-formula prefix after leading whitespace is emitted as
literal text, while validated Decimal amounts—including negative refunds and reversals—remain
numeric. Protected audit history records the member, scope, filters, row count, and time without
recording the exported financial contents.

## 13. Spending and surplus calculations

All currency calculations use exact decimal arithmetic and round to cents at defined boundaries.

Definitions:

```text
allocatable_amount =
    planned_income
  - planned_fixed_expenses
  - required_debt_payments
  - scheduled_goal_contributions
  - safety_buffer

unallocated_excess =
    allocatable_amount
  - total_variable_spending_budget

spending_remaining =
    total_variable_spending_budget
  - actual_variable_spending

period_closing_surplus =
    actual_income_received
  - actual_fixed_expenses
  - current_income_funded_debt_payments
  - actual_goal_contributions
  - actual_variable_spending

closing_household_reserve =
    opening_household_reserve
  + period_closing_surplus
  - reserve_allocations_out
```

The default safety buffer is zero and may be configured later.

Example:

```text
Income                 $2,840.00
Required expenses     -$1,926.50
Goal contributions      -$350.00
Spending budget          -$420.00
Unallocated excess        $143.50
```

Unused category budget does not roll into the next category budget and does not automatically fund a goal. At period close, unused spending and unallocated excess become part of the persistent Household Reserve. The reserve is shown separately from new paycheck income and is never automatically available for spending.

A historical correction to a closed period posts only its net difference to the current Household Reserve. It does not rewrite later paycheck budgets or recurring schedules.

Money reserved for future credit-card settlement is tracked separately from the Household Reserve. It is unavailable for ordinary spending and is consumed when the associated card payment occurs.

If the result is negative, the UI displays a deficit and does not automatically reduce any plan.

## 14. Debts and payoff projections

A debt contains:

- Name and type
- Current balance
- APR
- Minimum or scheduled payment
- Payment recurrence and due date
- Interest/compounding method, monthly by default
- Optional recurring extra payment
- Optional payment components such as principal, interest, escrow, insurance, taxes, PMI, and fees
- One or more monthly funding installments
- Active/paid-off state

The monthly obligation may generate one or more one-way Budget occurrences. For the household mortgage, two configurable monthly installments fund one full monthly obligation; this is semi-monthly rather than biweekly. Each installment is assigned to its own paycheck period by date.

Mortgage principal and interest affect the loan projection. Escrow, insurance, taxes, PMI, and fees affect cash flow and expense reporting but do not reduce principal. The actual lender statement may replace estimated principal/interest allocation without changing future scheduled installment amounts.

An extra principal payment entered in a budget period changes that period and the projected payoff, not the recurring schedule.

Strategies:

- Minimum payments only
- Snowball: lowest balance first
- Avalanche: highest APR first
- Custom priority

Each projection displays payoff date, total interest, time saved, and interest saved. Projections are estimates based on supplied data and assumptions, not lender statements.

## 15. Goals

Goal types include Savings, Debt Payoff, and Investing.

A goal supports:

- Name and type
- Current amount
- Target amount
- Optional target date
- Recurring contribution per paycheck period
- Priority order
- Active/paused/completed state
- Optional automatic excess allocation

Default allocation order:

1. Fixed expenses and required debt payments
2. Scheduled goal contributions
3. Variable spending budgets
4. Remaining money stays unallocated

“Automatically send excess to goals” is off by default. If enabled, priority order determines where excess goes. If income is short, the default is “Do not reduce anything automatically.”

## 16. Manual accounts

The initial release stores lightweight manual accounts and balance snapshots:

- Account name and type
- Types: Checking, Savings, Cash, Credit Card, and Other
- Optional last four digits; full account and card numbers are not stored
- Current manually entered balance
- Balance timestamp
- Notes

An internal ledger records the account impact of income, expenses, transfers, debt payments, goal contributions, interest/fees, and balance adjustments. Manual balance snapshots remain reconciliation aids rather than the source of truth for paycheck-period planning. This boundary allows future CSV and bank integrations without redesigning Budget.

The allocation system maintains two distinct reserve concepts:

- **Household Reserve:** accumulated unallocated and unused paycheck-period money.
- **Credit-card Payment Reserve:** money already assigned to settle categorized card purchases.

Neither reserve is presented as a verified bank balance. Account snapshots allow the household to compare calculated and manually observed balances.

## 17. Notifications

The initial release includes optional in-app notifications for:

- Upcoming and overdue bills
- Expected paychecks not marked received
- Negative period projections
- Goal milestones
- Missing or overdue verified backups
- New authenticated sessions and repeated login/MFA failures
- Failed audit-integrity verification

Email, SMS, and push notifications are deferred.

## 18. Protected audit history

### 18.1 Security objective

Audit events must be tamper-resistant against application users and ordinary application code, and tamper-evident if database rows are altered or removed outside the application.

No self-hosted design can make records absolutely immutable from a person who controls the operating system, database superuser, application secrets, and every backup destination. The design therefore uses independent layers so unauthorized changes are difficult and detectable.

### 18.2 Events captured

Material events include:

- Create, update, archive, cancel, and restore actions
- Period-specific overrides
- Schedule and boundary changes
- Moving an occurrence between periods
- Marking income received or an expense paid
- Manual and CSV transaction creation, plus transaction exports
- CSV import batches and duplicate decisions
- Debt, goal, and category changes
- Login, logout, failed login, audit export, and integrity-check results
- Viewing detailed audit records

### 18.3 Event contents

Each event contains:

- Immutable event ID and monotonic sequence
- Household ID
- Authenticated actor ID
- Server-generated timestamp and household timezone
- Action and entity type/ID
- Period and source references when applicable
- Canonical before and after values
- Optional user-supplied reason
- Request/correlation ID
- Previous record hash and current record hash

Passwords, password hashes, session tokens, encryption keys, Tailscale credentials, and complete raw CSV files must never be logged.

### 18.4 Database controls

- Audit tables live in a dedicated schema owned by a non-login owner role.
- The runtime role has no `UPDATE`, `DELETE`, `TRUNCATE`, ownership, DDL, or grant privileges on audit objects.
- Runtime audit writes occur only through a narrowly scoped database function or trigger.
- Relevant domain changes and their audit events commit in the same database transaction.
- Database triggers reject attempted mutation or deletion of audit rows by non-owner roles.
- Deployment migrations use a separate administrative role that is unavailable to the running application.

### 18.5 Integrity chain and checkpoints

- Each household audit stream is hash-chained using a canonical event representation and the prior event hash.
- A daily checkpoint records the latest sequence, event count, and chain head.
- The checkpoint is copied outside the VM to a versioned backup location.
- Prefer signing the checkpoint with a key held outside the VM. The signing key must not be stored in the application database.
- Verification runs at application startup, daily, before export, and on demand.
- A failed or incomplete verification produces a prominent warning and a security notification; it never silently marks the log valid.

### 18.6 Audit interface

- Audit records are viewable and exportable but have no edit, delete, or clear controls.
- Expanded events show human-readable before/after differences.
- The UI displays verification time, record count, external checkpoint time, and integrity status.
- Audit retention is indefinite for the initial household deployment.

## 19. Suggested implementation architecture

This is the recommended low-complexity starting stack; it may be changed without changing product behavior.

- Server application: Python/Django monolith
- UI: server-rendered templates with HTMX/Alpine-style interactions and utility CSS
- Charts: lightweight browser charting library
- Database: PostgreSQL
- Packaging: Docker Compose
- Private access: Tailscale on the Linux VM and approved client devices
- Reverse proxy: private-only HTTPS endpoint
- Background work: lightweight scheduled jobs; no separate task cluster initially
- Installability: responsive progressive web app shell, without offline financial data
- Security verification target: OWASP ASVS 5.0 Level 2 where applicable

Container boundaries:

- Web application
- PostgreSQL database, not exposed beyond the private container network
- Scheduled backup/integrity job
- Private reverse proxy

## 20. Deployment and backup requirements

- The app listens only on a private interface reachable through Tailscale.
- No router port forwarding is required.
- Tailscale device approval and least-privilege service grants are required.
- Household clients may reach the private HTTPS application endpoint but not PostgreSQL, Docker, or unrelated host services.
- Windows and Linux host firewalls remain enabled with default-deny inbound rules appropriate to each host.
- Separate application logins remain required even on the private network.
- MFA is required for Tailscale identities and application accounts after enrollment.
- Secrets are injected at deployment and never committed to source control.
- Database backups are encrypted, versioned, and copied outside the VM daily.
- At least one backup location must survive deletion or corruption of the VM.
- A periodic disconnected or independent encrypted backup is required.
- Restore instructions are documented and a test restore is performed at least quarterly.
- The Windows host, Linux VM, and home internet must be running for remote access.

The application and database must remain portable so the same containers can later move to a hosted Linux server with a domain and public HTTPS authentication.

## 21. Non-functional requirements

- Responsive from approximately 375px phone width through large desktop screens.
- Browser support: current and previous major Chrome, Edge, and Firefox on desktop; current Safari and Firefox on iPhone/iPad; current Chrome and Firefox on Android. Automated coverage uses Chromium, Firefox, and WebKit engines, supplemented by mobile-device smoke tests.
- Keyboard-accessible desktop interactions and touch targets suitable for phones/tablets.
- Accessible color contrast in both themes; color is never the only status indicator.
- Server-side authorization on every household-scoped operation.
- CSRF protection, secure server-side sessions, restrictive security headers, login rate limiting, MFA, and framework-managed password hashing.
- Sensitive pages use no-store caching and no authentication or financial data is stored in browser local storage.
- CSV upload validation, bounded parsing, formula-safe export, and temporary-file cleanup are required.
- Application containers run without unnecessary privileges and PostgreSQL is not exposed outside its container network.
- Dependencies and container images are pinned, scanned, and updated through a documented security process.
- Database timestamps stored consistently and displayed in the household timezone.
- Financial arithmetic uses decimal types, never binary floating point.
- Common dashboard and period views should feel immediate on the two-user deployment.
- Audit or financial write failures fail the full transaction rather than leaving partially recorded state.

## 22. MVP delivery sequence

### Phase 1 — Foundation

- Project and deployment skeleton
- Authentication, MFA/recovery, secure sessions, household membership, theme, responsive navigation
- Tailnet access policy, private HTTPS, host firewall rules, and hardened container baseline
- Database roles, audit foundation, encrypted backup, external checkpoint, and integrity-check skeleton
- Automated secret, dependency, authorization, and security-header tests

### Phase 2 — Scheduling and Budget

- Shared recurrence engine
- Income anchors and paycheck-period generation
- Fixed expenses, generated occurrences, period overrides, and safe deletion
- Budget calculations and dashboard
- Household Reserve lifecycle and historical correction deltas

### Phase 3 — Spending

- Categories and variable budgets
- Manual transactions
- CSV mapping, preview, duplicate detection, and batch audit
- CSV upload limits, bounded parsing, temporary-file cleanup, and formula-safe export
- Manual accounts, internal ledger, transfers, credit-card purchases, and card-payment reserve

### Phase 4 — Debts and Goals

- Debt schedules and payoff simulations
- Mortgage component split and twice-monthly installment schedule
- Goal contributions, priorities, and optional excess allocation

### Phase 5 — Hardening

- Protected audit UI and external checkpoints
- In-app notifications
- ASVS review, threat-model review, dependency/container scan, and incident-response exercise
- Responsive, accessibility, quarterly restore procedure, and end-to-end verification

## 23. Critical acceptance criteria

1. A Thursday anchor paycheck creates a Thursday-through-Wednesday period.
2. Changing a future payday regenerates only affected future periods after preview and confirmation.
3. A one-time bonus does not create a new period by default.
4. Two anchor paychecks on the same date create one period boundary.
5. Editing a generated income or debt entry from Budget does not change its source schedule.
6. Editing a source schedule does not overwrite a period-specific override.
7. A bill defaults to the period containing its due date and can be moved once.
8. Deleting a recurring item requires a scope choice and confirmation; history remains.
9. CSV import shows mappings, preview, duplicates, and category gaps before any write.
10. Unallocated excess is mathematically correct and visibly separate from spending remaining.
11. A shortfall is shown without automatic plan reduction.
12. Snowball, avalanche, custom, and minimum-only debt projections use exact decimal calculations.
13. Both household members have equal domain permissions and distinct audit identities.
14. Ordinary application credentials cannot update, delete, or truncate audit records.
15. Modifying or deleting a stored audit row causes integrity verification to fail.
16. A failed audit event prevents its associated financial change from committing.
17. The application is unreachable from the public internet in the private deployment.
18. A documented backup can restore the household, financial data, and audit chain.
19. Unapproved Tailscale devices cannot reach the application, and approved devices can reach only permitted services.
20. Both application accounts require MFA and have tested offline recovery codes.
21. Password or MFA recovery terminates existing sessions and records an audit event.
22. Session cookies and browser storage meet the requirements in `SECURITY_PLAN.md`.
23. Cross-household and direct-object authorization tests fail closed.
24. Oversized, malformed, and non-CSV uploads are rejected without persistence or execution.
25. CSV exports neutralize spreadsheet-formula payloads.
26. PostgreSQL and Docker administration are unreachable from household client devices.
27. Production containers have no unnecessary privilege, privileged mode, or Docker-socket access.
28. Dependency, container, and secret scans pass the documented release threshold.
29. A quarterly restore reproduces the expected data and validates against an external audit checkpoint.
30. The lost-device and credential-rotation incident procedures are successfully rehearsed.
31. A credit-card purchase reduces its category budget once, increases card liability, and creates an equal card-payment reserve without being counted again as an expense at payment.
32. A credit-card payment reduces checking, card liability, and any associated card-payment reserve using a transfer/debt-settlement transaction.
33. Interest and fees are reported as expenses while principal settlement is not categorized spending.
34. Closing a period moves unused spending and unallocated excess into Household Reserve without treating it as new income in the next period.
35. Correcting a closed period posts only the resulting reserve delta and does not rewrite future budgets.
36. A mortgage with two monthly installments creates two budget occurrences whose monthly total equals the configured obligation.
37. Mortgage escrow and other non-principal components affect cash flow but do not reduce projected loan principal.
38. Account transfers do not alter spending-category totals.
39. Supported desktop and mobile Firefox smoke tests pass before release.

## 24. Design references

The approved direction is documented in `design/mockups/`. Mockup names and sample figures are illustrative; this specification is authoritative for calculations and behavior.

Implementation-planning references:

- `DATA_MODEL.md`
- `WORKFLOWS.md`
- `CALCULATION_RULES.md`
- `IMPLEMENTATION_PLAN.md`

## 25. Security references

- Security plan: `SECURITY_PLAN.md`
- OWASP ASVS: https://owasp.org/www-project-application-security-verification-standard/
- OWASP Logging Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Logging_Cheat_Sheet.html
- OWASP Session Management: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
- OWASP File Upload: https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP Cryptographic Storage: https://cheatsheetseries.owasp.org/cheatsheets/Cryptographic_Storage_Cheat_Sheet.html
- PostgreSQL privileges: https://www.postgresql.org/docs/current/ddl-priv.html
- Tailscale security best practices: https://tailscale.com/docs/reference/best-practices/security
- Tailscale firewall behavior: https://tailscale.com/docs/reference/faq/firewall-ports
