# Household Budget Application — Workflow and State Models

Status: Milestone 4 scheduling and paycheck-period workflows implemented
Last updated: 2026-08-22

## 1. Paycheck-period lifecycle

```mermaid
stateDiagram-v2
    [*] --> Projected: anchor schedule generates period
    Projected --> Projected: future schedule revision regenerates
    Projected --> Open: boundary paycheck date arrives
    Open --> ClosingReview: next anchor boundary arrives
    ClosingReview --> Open: user postpones close
    ClosingReview --> Closed: confirm actuals and reserve posting
    Closed --> Reopened: explicit historical correction
    Reopened --> Closed: save correction and post reserve delta
    Closed --> [*]

    Open --> BoundaryReview: paycheck arrives early or late
    BoundaryReview --> Open: keep scheduled boundary
    BoundaryReview --> Open: accept actual boundary and preview changes
```

Rules:

- Opening a new period never requires the previous period to be irreversibly locked.
- Closing posts unallocated excess and unused spending to Household Reserve.
- Reopening a closed period preserves its original closing record and creates a new closing revision.
- The difference between closing revisions posts as a current reserve adjustment; later planned periods are not rewritten.

## 2. Source schedule and occurrence lifecycle

```mermaid
stateDiagram-v2
    [*] --> Scheduled: generated from immutable source revision
    Scheduled --> Moved: assigned to another pay period
    Scheduled --> Overridden: amount/date/category changed locally
    Moved --> Overridden: local fields changed
    Scheduled --> Completed: received or paid
    Moved --> Completed: received or paid
    Overridden --> Completed: received or paid
    Scheduled --> Cancelled: remove this occurrence
    Moved --> Cancelled: remove this occurrence
    Overridden --> Cancelled: remove this occurrence
    Completed --> Corrected: actual entry reversed/replaced
    Corrected --> Completed: corrected actual reconciled
    Cancelled --> [*]
    Completed --> [*]
```

A source edit creates a new effective-dated revision. It regenerates only compatible, unmodified future occurrences. Moved, overridden, completed, and cancelled occurrences retain their local state and provenance.

## 3. Paycheck boundary generation

```mermaid
flowchart LR
    A[Active income sources] --> B{Starts a budget period?}
    B -- No --> C[Generate income occurrence only]
    B -- Yes --> D[Generate anchor occurrence dates]
    D --> E[Apply weekend/holiday policy]
    E --> F[Combine anchors on the same local date]
    F --> G[Sort distinct anchor dates]
    G --> H[Period = anchor date through day before next anchor]
    H --> I[Assign due items by effective date]
    I --> J[Preview shortened, lengthened, merged, or new periods]
```

Default weekend/holiday policy is previous business day. If the actual arrival differs from the projection, the app asks whether the boundary should move.

## 4. Actual transaction classification

```mermaid
flowchart TD
    T[Enter or import transaction] --> K{Transaction type}
    K -->|Income| I[Increase asset and record income]
    K -->|Cash/checking expense| E[Reduce asset and increase category spending]
    K -->|Credit-card purchase| C[Increase card liability and category spending]
    C --> R[Increase card-payment reserve]
    K -->|Account transfer| X[Move value between accounts; no spending]
    K -->|Card payment| P[Reduce checking and card liability]
    P --> Q[Consume card-payment reserve first]
    Q --> D[Excess payment becomes current-income-funded debt payoff]
    K -->|Interest or fee| F[Increase card liability and expense]
    K -->|Partial card refund| U[Reduce card liability and category spending]
    U --> V[Release only payment reserve still available]
    K -->|Goal contribution| G[Move value and update goal progress]
    K -->|Balance adjustment| B[Reconciliation-only ledger adjustment]
```

This separation prevents a categorized credit-card purchase and its later payment from both appearing as spending.

## 5. Credit-card reserve lifecycle

```mermaid
stateDiagram-v2
    [*] --> Available: categorized card purchase reserves cash
    Available --> Increased: additional purchase
    Increased --> Available: derived reserve balance updated
    Available --> Reduced: refund or purchase reversal
    Reduced --> Available: derived reserve balance updated
    Available --> Consumed: card payment uses reserved amount
    Consumed --> Available: reserve remains after partial payment
    Consumed --> Empty: payment consumes full reserve
    Empty --> [*]
```

Reserve states are derived from append-only entries. If a card payment exceeds its reserve, the
excess is debt payoff funded by the current period or Household Reserve as explicitly selected.
Reversals also append corrections: a returned payment restores only the amount still backed by
active card purchases, while any portion already canceled by a refund remains budget-neutral.
Multiple partial refunds link to the original purchase and accumulate only to its original amount;
neither the purchase nor an earlier refund is edited.

## 6. Twice-monthly mortgage workflow

```mermaid
flowchart LR
    M[Monthly mortgage obligation] --> S[Component split]
    S --> PI[Principal and interest]
    S --> ES[Escrow: taxes and insurance]
    S --> O[PMI, fees, or other]

    M --> P1[Installment 1 on configured date]
    M --> P2[Installment 2 on configured date]
    P1 --> B1[Budget occurrence in containing paycheck period]
    P2 --> B2[Budget occurrence in containing paycheck period]
    B1 --> A[Aggregate lender payment cycle]
    B2 --> A
    A --> L[Apply principal and interest to loan projection]
    A --> C[Report escrow and other as cash-flow expenses]
```

Rules:

- The two installments must total the configured full monthly obligation unless an intentional extra-principal amount is added.
- The schedule uses two selected monthly dates, not every 14 days.
- The lender's actual statement allocation supersedes estimates for history.
- Escrow does not reduce mortgage principal.

## 7. Period close and Household Reserve

```mermaid
flowchart TD
    O[Opening Household Reserve] --> C[Closing calculation]
    I[Actual period income] --> C
    F[Actual fixed and debt funding] --> C
    G[Actual goal contributions] --> C
    S[Actual variable spending] --> C
    C --> D{Closing surplus or deficit}
    D -->|Surplus| R[Append positive Household Reserve entry]
    D -->|Deficit| N[Append negative reserve entry or show unresolved deficit]
    R --> V[Next dashboard shows reserve separately]
    N --> V
    V --> X{User assigns reserve?}
    X -->|No| V
    X -->|Goal, debt, or spending| A[Append explicit reserve allocation]
```

Household Reserve never becomes paycheck income automatically.

## 8. CSV import lifecycle

```mermaid
stateDiagram-v2
    [*] --> Uploaded
    Uploaded --> Rejected: type, size, encoding, or structure invalid
    Uploaded --> Mapped: columns selected
    Mapped --> Previewed: rows parsed and normalized
    Previewed --> ReviewRequired: duplicates or missing categories
    ReviewRequired --> Previewed: user resolves decisions
    Previewed --> Committed: explicit confirmation
    Previewed --> Abandoned: cancel or expiry
    Committed --> Reconciled: imported entries matched to plans
    Rejected --> [*]
    Abandoned --> [*]
    Reconciled --> [*]
```

No JournalEntry is created before `Committed`. Repeating a committed batch with the same idempotency key cannot duplicate transactions.
The file is parsed under byte/row/column/cell limits and is never retained as an upload. Confirmation
commits every accepted expense and its audit history atomically, then scrubs staged raw cells. A
failure rolls back the whole financial commit and leaves the reviewed staging data available.

## 9. Audit write and verification

```mermaid
sequenceDiagram
    participant U as Household member
    participant A as Application
    participant D as Domain tables
    participant L as Append-only audit schema
    participant C as External checkpoint

    U->>A: Submit financial change
    A->>D: Begin transaction and validate authorization
    A->>D: Write domain change
    A->>L: Append canonical before/after event
    alt audit append succeeds
        D-->>A: Commit both writes
        A-->>U: Confirm change
    else audit append fails
        D-->>A: Roll back domain change
        A-->>U: Report failure
    end
    A->>L: Verify chain on schedule/startup/export
    L-->>C: Copy/sign chain-head checkpoint outside VM
```

## 10. Goal and reserve allocation

```mermaid
flowchart TD
    I[Pay-period income] --> F[Fixed expenses and required debt]
    F --> G[Scheduled goal contributions]
    G --> S[Variable spending budget]
    S --> U[Current-period unallocated excess]
    U --> C[Household Reserve at close]
    C --> A{Automatic excess allocation enabled?}
    A -- No --> K[Keep visible and unassigned]
    A -- Yes --> P[Apply configured goal priorities]
```

The automatic-excess setting remains off by default.
