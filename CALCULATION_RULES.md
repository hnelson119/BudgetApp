# Household Budget Application — Calculation Rules and Golden Cases

Status: Pre-build test baseline
Last updated: 2026-08-21

The examples in this document become automated tests. All money uses exact Decimal arithmetic. Display values round to cents using one documented application-wide rounding mode; intermediate debt calculations preserve additional precision until the lender-cycle posting step.

## 1. Core definitions

### Planned paycheck-period allocation

```text
allocatable_amount =
    planned_income
  - planned_fixed_expenses
  - current_income_funded_required_debt
  - scheduled_goal_contributions
  - safety_buffer

unallocated_excess =
    allocatable_amount
  - total_variable_spending_budget

spending_remaining =
    total_variable_spending_budget
  - actual_variable_spending
```

Card-payment settlement funded by a previously created Credit-card Payment Reserve is excluded from `current_income_funded_required_debt` because that cash was already reserved when the purchase occurred.

### Final period result

```text
period_closing_surplus =
    actual_income_received
  - actual_fixed_expenses
  - current_income_funded_debt_payments
  - actual_goal_contributions
  - actual_variable_spending
  - safety_buffer_used

closing_household_reserve =
    opening_household_reserve
  + period_closing_surplus
  - explicit_reserve_allocations_out
```

Equivalently, when actual required costs and goals equal their plans:

```text
period_closing_surplus = unallocated_excess + spending_remaining
```

The equality does not hold when actual fixed costs, income, goals, or debt funding differ from plan; the final formula is authoritative.

### Reserve balances

```text
household_reserve_balance = sum(household_reserve_entries)

card_payment_reserve(card) =
    categorized_card_purchase_reservations
  - refunds_and_reversals
  - reserve_consumed_by_card_payments
```

Reserve balances are allocation balances, not verified balances at a bank.

## 2. Sign and classification rules

- UI amounts are entered as positive magnitudes; transaction type determines ledger direction.
- Income increases an asset account and income total.
- Cash/checking expense decreases an asset and increases categorized spending.
- Credit-card purchase increases liability and categorized spending.
- Account transfer changes account balances but not income or spending.
- Debt principal payment reduces an asset and liability but is not categorized consumption spending.
- Interest, lender fees, and card fees are expenses.
- Goal transfer moves an asset and updates goal progress; it is shown as a goal contribution, not categorized spending.
- Balance adjustment corrects reconciliation and is never silently treated as income or expense.

## 3. Golden case A — Basic paycheck period

Inputs:

```text
Planned/received income          $2,840.00
Fixed expenses and debt         $1,926.50
Goal contributions                $350.00
Variable spending budget          $420.00
Actual variable spending          $133.60
Opening Household Reserve           $0.00
```

Expected:

```text
Allocatable amount                $563.50
Unallocated excess                $143.50
Spending remaining                $286.40
Period closing surplus            $429.90
Closing Household Reserve         $429.90
```

Assertions:

- The dashboard shows `$143.50` current-period unallocated and `$286.40` spending remaining as separate values.
- After close, `$429.90` is added to Household Reserve.
- The next paycheck period does not add `$429.90` to paycheck income.

## 4. Golden case B — Existing reserve carry-forward

Use Golden case A with an opening Household Reserve of `$500.00`.

Expected closing reserve:

```text
$500.00 + $429.90 = $929.90
```

The next period shows `$929.90 Household Reserve` separately from that period's planned income.

## 5. Golden case C — Explicit reserve allocation

Starting Household Reserve: `$929.90`.

User assigns `$300.00` to Emergency Fund and `$100.00` as extra Visa principal.

Expected:

```text
Reserve allocation out            $400.00
Remaining Household Reserve       $529.90
Emergency Fund actual increase    $300.00
Extra Visa principal              $100.00
```

Neither allocation is new income. Each creates its own ledger/reserve entries and audit events.

## 6. Golden case D — One-time bonus

Base planned income is `$2,650.00`. A `$190.00` one-time bonus arrives inside the period and does not have `starts_budget_period` enabled.

Expected:

- The existing period boundaries do not change.
- Actual income becomes `$2,840.00`.
- With no new allocation, unallocated excess increases by `$190.00`.
- The bonus occurrence is marked “This period only.”

## 7. Golden case E — Credit-card purchase and later payment

### Purchase period

User buys `$75.00` of groceries on Visa.

Expected:

```text
Groceries actual spending          +$75.00
Visa liability                     +$75.00
Visa Payment Reserve               +$75.00
Checking balance change              $0.00
```

### Later payment period

User pays `$75.00` from Checking to Visa.

Expected:

```text
Checking                           -$75.00
Visa liability                     -$75.00
Visa Payment Reserve               -$75.00
New categorized spending             $0.00
Current-income-funded debt payoff    $0.00
```

Assertion: groceries are counted exactly once, on the purchase date.

## 8. Golden case F — Card payment containing old-debt payoff

Opening Visa Payment Reserve: `$75.00`. The household has pre-existing revolving debt and has budgeted `$100.00` of current income for payoff. It pays `$175.00` from Checking.

Expected allocation:

```text
Reserved purchase settlement       $75.00
Current-income-funded debt payoff  $100.00
Total checking reduction           $175.00
Total Visa liability reduction     $175.00
Closing Visa Payment Reserve         $0.00
New categorized spending             $0.00
```

If the payment is only `$125.00`, reserve settlement is `$75.00` and current-income-funded payoff is `$50.00`; the remaining `$50.00` planned payoff is marked underpaid rather than silently reclassified.

## 9. Golden case G — Card interest and fees

Visa posts `$20.00` interest and a `$5.00` late fee.

Expected:

```text
Visa liability                     +$25.00
Interest expense                   +$20.00
Fee expense                         +$5.00
Card Payment Reserve                 $0.00 change
```

Interest and fees are not treated as categorized purchases funded from a variable shopping category. They affect debt projections and required funding.

## 10. Golden case H — Twice-monthly mortgage

Configuration:

```text
Full monthly obligation          $1,350.00
Principal + interest component  $1,100.00
Escrow component                  $250.00
Installment 1                     $675.00
Installment 2                     $675.00
```

Expected:

- Two monthly Budget occurrences are generated on the configured dates.
- Each occurrence belongs to the paycheck period containing its date.
- The monthly installment total is `$1,350.00`.
- The loan projection uses the `$1,100.00` principal-and-interest component.
- The `$250.00` escrow component affects cash flow and housing reporting but never reduces mortgage principal.

If the second installment is increased by `$100.00` with “Extra principal” selected:

```text
Monthly cash paid                 $1,450.00
Scheduled obligation             $1,350.00
Extra principal                    $100.00
Future installment schedule          unchanged
```

The actual lender statement may override the estimated principal/interest split for history.

## 11. Golden case I — Paycheck boundary dates

Anchor paychecks are expected Thursday, August 20 and Thursday, August 27, 2026.

Expected period:

```text
Start date       2026-08-20
Exclusive end    2026-08-27
Displayed range  Thu Aug 20 – Wed Aug 26
```

A bill due Wednesday, August 26 belongs to this period. A bill due Thursday, August 27 belongs to the next period.

## 12. Golden case J — Same-day anchor paychecks

Two different income sources both have `starts_budget_period` enabled and arrive Thursday, August 20.

Expected:

- One boundary is created for August 20.
- Both income occurrences belong to the same new period.
- Their amounts are added to the period income independently.

## 13. Golden case K — Early or late paycheck

A paycheck expected Thursday arrives Wednesday night.

Expected default behavior:

- The expected budget boundary remains Thursday until the user responds.
- The app offers “Keep Thursday boundary” or “Start period Wednesday.”
- Either choice previews bills and occurrences that would move.
- No historical boundary changes silently.

An employer holiday rule may project the previous business day in advance; that projected adjusted date is not considered an unexpected arrival.

## 14. Golden case L — Moved bill

An Internet bill due August 27 defaults to the period beginning August 27. The user moves only that occurrence into August 20–26.

Expected:

- The August 20–26 period gains the bill.
- The next period loses only that occurrence.
- Future Internet occurrences remain assigned by due date.
- The occurrence stores original and assigned period IDs.
- The move is audited.

## 15. Golden case M — Closed-period correction

Golden case A originally closes with `$429.90` surplus. Later, an omitted `$25.00` cash expense is added to that closed period.

Expected:

```text
Corrected period surplus            $404.90
Reserve correction entry            -$25.00
Change to future planned budgets       $0.00
```

The original closing revision remains visible in audit history.

## 16. Golden case N — Shortfall

Inputs:

```text
Income                            $1,500.00
Fixed expenses and debt          $1,400.00
Scheduled goals                    $200.00
Variable spending budget           $300.00
```

Expected:

```text
Allocatable amount                -$100.00
Unallocated after spending plan   -$400.00
```

The application shows a `$400.00` planned deficit and does not automatically reduce goals, expenses, or spending budgets. A user must explicitly edit or fund the shortfall from Household Reserve.

## 17. Debt projection rules

- Default fixed-loan periodic interest uses the configured APR and compounding method.
- Monthly method uses `APR / 12` per monthly cycle.
- Daily method uses the configured day-count basis and actual days between posting dates.
- Interest posts before principal allocation according to the selected model.
- Payment amount above interest and required fees reduces principal.
- Mortgage escrow, taxes, insurance, and PMI are excluded from principal amortization.
- Minimum-only, snowball, avalanche, and custom strategies use the same underlying interest engine.
- Snowball directs available extra payment to the lowest eligible balance.
- Avalanche directs available extra payment to the highest effective APR.
- A paid-off debt's freed required payment rolls to the next strategy debt beginning with the next modeled payment cycle.
- New card purchases are excluded from payoff projections unless the scenario explicitly includes them.
- APR changes and promotional periods are effective-dated revisions.
- Projections show assumptions and remain estimates; recorded lender statements control historical actuals.

## 18. Reconciliation variance

```text
account_variance = observed_balance_snapshot - calculated_ledger_balance
```

A nonzero variance is displayed for investigation. The app never silently changes historical transactions to force a match. A user may add an explicit Balance Adjustment with a reason, which is audited.
