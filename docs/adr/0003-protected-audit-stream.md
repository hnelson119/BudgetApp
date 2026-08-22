# ADR 0003: Protected append-only audit stream

- Status: Accepted
- Date: 2026-08-21

## Context

Both household members can edit financial records, but audit history must not
be alterable through the application or by compromised runtime credentials.

## Decision

Write canonical, hash-chained audit events in the same database transaction as
material domain changes. Store them in a separately owned PostgreSQL schema.
The runtime role receives append-only execution rights through a controlled
database function and no update/delete privileges. A separate job verifies the
chain and places signed chain-head checkpoints outside the VM.

## Consequences

- The application will expose no audit edit or delete path.
- A failed audit append rolls back the associated financial mutation.
- Hash verification detects tampering; external checkpoints improve detection
  when the database or VM itself is compromised.
- Database superusers and host administrators remain a trust boundary, so
  encrypted backups, external checkpoints, and operational monitoring remain
  required.
