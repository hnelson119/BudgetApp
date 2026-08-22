# ADR 0002: Paycheck-anchored budget periods

- Status: Accepted
- Date: 2026-08-21

## Context

Calendar-week budgets do not match the household's cash flow. Income sources
can change employers, schedules, or arrival dates.

## Decision

A budget period begins at one selected paycheck anchor and ends immediately
before the next anchor. Boundaries derive from effective-dated income schedules.
Same-day anchors create one boundary, and an unexpected early or late arrival
requires a user decision before changing a boundary. Bills default to the period
containing their due date but an individual occurrence can be moved.

## Consequences

- Weekly, biweekly, and future employer schedules use one period model.
- Schedule revisions do not silently rewrite closed history.
- The UI must preview items affected by a proposed boundary change.
