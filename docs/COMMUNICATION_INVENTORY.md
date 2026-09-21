# Application communication inventory

Status: implemented; release verification pending
Last reviewed: 2026-09-20

The authoritative structured catalog is `docs/communication-inventory.json`. It records each
communication's phase, source, fixed destination, transport, protection, data class, user-control
status, and implementation evidence. The local and CI validator requires the catalog to remain
complete and synchronized with the deployment allowlists.

## Runtime and management paths

| Flow | Destination and transport | Purpose and boundary |
| --- | --- | --- |
| Household browser access | One exact Tailscale hostname, HTTPS TCP 443 | Private application pages and forms from individually authenticated, approved devices. |
| Administrator SSH | Dedicated VM, SSH TCP 22 over Tailscale | Key-authenticated deployment and maintenance by the owner-administrator only. |
| Tailscale loopback relay | `127.0.0.1:8000`, HTTP over host loopback | The sole narrow plaintext hop after Tailscale TLS termination; never bound to LAN or public interfaces. |
| Ingress to web | `web:8443`, mutually authenticated HTTPS | Fixed nginx-to-Gunicorn request boundary on the internal frontend network. |
| Services to PostgreSQL | `db:5432`, PostgreSQL mutual TLS | Nine exact certificate identities mapped to purpose-specific roles on the internal backend network. |
| Security-log delivery | `/run/security-log/security.sock`, Unix datagram | Bounded redacted security records from the web process to its isolated collector. |
| Security-log archive | Collector-only local volume | Networkless validated archive and alert stream storage. |
| Backup repository | Pre-existing `/repository` bind mount | Encrypted Restic backups, restores, key rotation, and non-sensitive freshness checks without a remote application destination. |
| Audit checkpoints | Pre-existing `/checkpoints` bind mount | Signed audit-chain heads written by the purpose-bound integrity service. |
| Host Docker control | Local host Unix socket | Root-owned systemd units and authenticated administrator commands manage the fixed Compose project; containers never receive the socket. |

## Secure failure behavior

The structured inventory records a mandatory failure behavior for every runtime and management
flow. The production application has no general outbound network client. Its only runtime resource
connections are the fixed PostgreSQL mutual-TLS path and the local security-log datagram socket.

- A PostgreSQL outage produces a sanitized, non-cacheable readiness `503` with a bounded retry hint;
  liveness remains database-independent. Application requests retain the generic error boundary,
  database transactions roll back, and neither plaintext nor password authentication is enabled as
  an availability fallback.
- Security-log delivery has a 250 ms socket timeout. Socket, size, or encoding failure emits only a
  fixed redacted fallback record to stderr, so an unavailable collector cannot leak the original
  record or block a request indefinitely. Collector validation, archive-write, fsync, or healthcheck
  failures remain visible and cannot grant Django access to the archive.
- Browser, SSH, loopback-relay, and nginx-to-Gunicorn failures close the affected path. They never
  enable public/LAN exposure, password SSH, a different upstream, plaintext transport, or a forged
  trusted-scheme signal.
- Backup, restore, key-rotation, checkpoint, and Docker-control failures return nonzero and preserve
  the last verified state. No unverified backup, unsigned checkpoint, broadened privilege, or
  self-repairing container is accepted as success.

These controls implement the repeatable repository boundary for ASVS `v5.0.0-16.5.2`. Dated
release-candidate outage observation remains required before marking the control verified.

Frontend and backend Docker networks are internal. The only host publish is the ingress relay's
exact IPv4 loopback port. The relay's only proxy destination is `https://web:8443`; Django's only
network backend is `db:5432`. The web application makes no HTTP, mail, remote-file, webhook, bank,
cloud-storage, or telemetry call. Hardened settings explicitly select Django's dummy email backend
so the framework's default SMTP implementation cannot become an accidental communication path.

## External services

The production application containers have no general external route. External dependencies occur
only at these surrounding lifecycle boundaries:

- the VM host and approved household devices use Tailscale coordination and relay infrastructure
  for private identity, overlay connectivity, MagicDNS, and Serve TLS;
- the trusted development/release environment uses GitHub for source review, CI, and the pinned
  ASVS source;
- image builders obtain hash-pinned Python packages from PyPI, lockfile-pinned browser-test
  packages from npm, and digest-pinned base/scanner images from the registries named in reviewed
  build definitions; and
- a trusted maintainer periodically obtains the breached-password corpus with HIBP's official
  downloader, verifies it locally, packages only the reviewed hash-only subset, and deletes the
  transient source. The application never contacts HIBP.

The encrypted backup and signed-checkpoint destinations are administrator-provisioned filesystem
mounts, not user-controlled URLs. If the host backs either mount with network storage, that host
transport and its authentication, encryption, availability, and recovery controls must be added to
the inventory before use.

## User-provided destinations and change control

The current release accepts no user-provided external location. There are no URL-fetch, webhook,
remote import, email-delivery, bank-sync, federated identity, or proxy features. Production rejects
external redirect allowlist entries. URL parsing in the application only validates or encodes local
values; it does not open a connection.

Adding bank synchronization or any other integration requires all of the following before release:

1. add the service and every DNS name, IP range where unavoidable, protocol, port, trust root,
   authentication method, data class, timeout, size limit, retry/failure behavior, and owner to the
   structured inventory;
2. establish a fixed outbound allowlist and a least-privilege network attachment rather than
   granting general egress;
3. prohibit user-controlled scheme, authority, port, credentials, redirects, and DNS rebinding, or
   document and test strict validation if the product requirement truly needs a user destination;
4. define secret rotation, logging/redaction, privacy, outage, incident, and removal behavior; and
5. update the production boundary probe, adversarial tests, threat model, and release evidence.

## Verification

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_communication_inventory.py
.\.venv\Scripts\python.exe -m pytest tests\test_communication_inventory.py tests\test_network_boundary.py tests\test_production_settings.py
```

The checker validates the exact catalog, evidence paths, service-network allowlist, fixed proxy and
database destinations, disabled SMTP backend, external-redirect prohibition, and all production
Python imports. It rejects runtime network clients and permits `socket` only in the two reviewed
Unix-datagram logging files, where internet socket families and connection helpers are prohibited.
Direct socket symbol imports, aliases, and dynamic member lookup are also rejected. This is a
reviewed direct-API inventory, not whole-program data-flow proof or an egress firewall; arbitrary
indirection and new network-capable dependencies still require source and deployment review.
This implements the repository-deliverable portion of ASVS `v5.0.0-13.1.1`; dated VM and approved
device observations remain part of release verification.
