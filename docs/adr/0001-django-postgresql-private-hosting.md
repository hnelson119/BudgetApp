# ADR 0001: Django, PostgreSQL, and private hosting

- Status: Accepted
- Date: 2026-08-21

## Context

The application holds sensitive household financial data, is shared by two
people, must work across desktop and mobile browsers, and initially runs on a
low-cost Linux VM hosted in Hyper-V.

## Decision

Use a server-rendered Django monolith on Python 3.12 with PostgreSQL, packaged
with Docker Compose. Bind the application to the host loopback interface and
provide remote access through private Tailscale HTTPS rather than router port
forwarding. Use Django 5.2 LTS for its extended support window.

## Consequences

- One deployment unit keeps operations reasonable for a two-person household.
- PostgreSQL supports transactional finance writes and stronger audit controls.
- Private ingress substantially reduces exposure but does not replace login,
  MFA, authorization, patching, encrypted backups, or monitoring.
- Public-domain hosting can be introduced later behind the same application
  boundary after a fresh threat-model review.
