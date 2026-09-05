# Private ingress and network-boundary runbook

This runbook establishes the release-only network boundary for the dedicated Linux VM. The budget
service is private: household browsers reach Tailscale Serve over HTTPS, Tailscale Serve proxies to
a secretless relay on IPv4 loopback, the Django application stays on internal Docker networks, and
PostgreSQL remains only on Docker's internal backend network. No router port is forwarded and
Tailscale Funnel is not enabled.

The disposable workstation probe is useful pre-deployment evidence, but it cannot satisfy
`NET-01`, `NET-02`, or the deployed portions of `NET-03` through `NET-06`. Those require the actual
VM, tailnet policy, firewall, certificate, approved devices, and an unapproved test device.

## 1. Identity and device prerequisites

1. Give each household member an individual identity-provider and Tailscale account. Do not share
   either account. Require MFA at the identity provider.
2. Enable [Tailscale device approval](https://tailscale.com/kb/1099/device-approval) before enrolling
   household devices. Keep newly enrolled devices unusable until an administrator approves them.
3. Review the [Tailscale security recommendations](https://tailscale.com/kb/1196/security-hardening)
   and retain device-key expiry. Revoke missing, replaced, or unused devices promptly.
4. Do not advertise the VM as an exit node or subnet router. The VM is a single tagged service,
   not a bridge to the home LAN.

The repository template at `deploy/network/tailnet-policy.example.hujson` uses Tailscale grants,
policy tests, a household-user group, an administrator group, and `tag:budget-server`. Replace every
`example.com` identity with the exact tailnet identities before submitting it in the access-control
editor. The editor must pass both policy tests. Do not retain a broad default `*` rule beside this
policy. See the current [grants syntax](https://tailscale.com/kb/1324/grants) and
[policy-test documentation](https://tailscale.com/kb/1337/acl-syntax#tests) before adapting it.

The spouse role receives only TCP 443. The owner/administrator role receives TCP 443 and SSH on TCP
22. Neither role receives PostgreSQL, application-upstream, or Docker API access. Tag the dedicated
VM interactively after its device is approved; avoid a reusable auth key. If an automation key ever
becomes necessary, make it preapproved, tagged, single-purpose, short-lived, and keep it outside the
repository and command history.

## 2. Application and proxy configuration

Production accepts exactly one lowercase Tailscale HTTPS hostname. Set the two non-secret values in
the deployment environment file to the VM's actual MagicDNS name:

```dotenv
APP_ENVIRONMENT=production
DJANGO_ALLOWED_HOSTS=budget-host.example-tailnet.ts.net
DJANGO_CSRF_TRUSTED_ORIGINS=https://budget-host.example-tailnet.ts.net
```

Replace the example; do not add loopback, wildcards, alternate hosts, IP addresses, or public
domains. Keep `.env` and `/etc/household-budget/household-budget.env` free of passwords and keys.
Set `BUDGET_SECRET_GID` to the numeric, non-root `household-budget-secrets` group documented in the
README, and do not add human users to it. All reusable values stay in root-owned mode-0440 files
under the mode-0700 `/etc/household-budget/secrets` directory. Compose grants the numeric group only
to secret-bearing containers, which continue to mount only their service-specific files.

Start the reviewed Compose project from `/opt/household-budget`:

```bash
docker compose up --build -d db
docker compose --profile maintenance run --rm db-bootstrap
docker compose --profile maintenance run --rm migrate
docker compose up --build -d web ingress
```

Confirm the VM's exact Tailscale DNS name with `tailscale status --json`, apply the dedicated server
tag, and configure [Tailscale Serve](https://tailscale.com/kb/1242/tailscale-serve) as the only TLS
proxy:

```bash
sudo tailscale set --advertise-tags=tag:budget-server
sudo tailscale serve --bg http://127.0.0.1:8000
sudo tailscale serve status --json
```

The resulting Serve document must contain only HTTPS on TCP 443, the exact VM hostname, and a `/`
handler proxying to `http://127.0.0.1:8000`. Its `AllowFunnel` entries must be absent or false. Never
run `tailscale funnel`; [Funnel](https://tailscale.com/kb/1223/funnel) intentionally exposes a
service to the public internet and is outside this product's scope.

Tailscale-provisioned certificate names can appear in public certificate-transparency logs, so use
a neutral machine name that reveals no family name or financial purpose. Application HTTP remains
on loopback only; the browser-facing connection is HTTPS.

### HTTP request-framing boundary

The repository pins the application-side message boundary to nginx receiving HTTP/1.1 and proxying
HTTP/1.1 to Gunicorn with complete request buffering enabled. The production-derived probe sends
three valid forms—a bodyless request, an explicit zero `Content-Length`, and a zero-length chunked
body—and six ambiguity cases: both framing headers in either order, conflicting duplicate lengths,
multiple transfer codings, whitespace before a header colon, and obsolete folded transfer syntax.
Every ambiguity includes a harmless trailing `/framing-canary` request where applicable. A pass
requires one `400` or `501` response, connection closure, and no second response.

`.github/workflows/http-framing.yml` runs this probe against the actual production nginx and
Gunicorn images for every pull request. That repeatable test covers the internal HTTP/1.1 boundary;
it does not claim that the release Tailscale edge has been observed. During release-candidate
testing, use an approved, bounded HTTP/2-capable client to send only `GET /health/live/` with a
declared `Content-Length` inconsistent with its ended DATA stream through the exact Tailscale HTTPS
hostname. If HTTP/3 is enabled for that candidate, repeat at HTTP/3. Pass only if the edge rejects or
resets the single stream without forwarding an application response. Do not pipeline another route,
scan other hosts, or retain raw private hostname, address, or response data.

### Outbound destination allowlist

The initial release has no external application dependency. Compose therefore acts as the
deployment allowlist: the exact service catalog and every service/network attachment are checked,
the frontend and backend networks are internal, and the repository key-rotation job has no network
at all. Host networking, ad hoc links, custom DNS, and host aliases fail the production-derived
probe. The Django server is configured only for `db:5432`; its required database connection must
succeed and a bounded external TCP connection must fail.

The secretless nginx relay is the narrow availability exception described in `M10-F014`: Docker
requires its non-internal ingress network to create the loopback host publish. It receives no
application secrets or database network and its running configuration must contain exactly one
static proxy destination, `web:8000`. Adding an integration, URL fetch, remote file load, proxy
destination, service, or network attachment requires an explicit allowlist change, updated tests,
and security review before deployment.

## 3. Host and home-network firewall

Before enabling UFW, verify SSH key login in a second Tailscale-connected terminal. Disable SSH
password authentication, keyboard-interactive authentication, and direct root login. Then apply a
deny-by-default host policy:

```bash
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow in on tailscale0 to any port 443 proto tcp comment 'Budget HTTPS via Tailscale'
sudo ufw allow in on tailscale0 to any port 22 proto tcp comment 'Admin SSH via Tailscale'
sudo ufw enable
sudo ufw status verbose
```

Do not add UFW rules for 8000, 5432, 2375, or 2376. Do not expose a Docker TCP socket. Keep Windows
Defender Firewall enabled on the Hyper-V host, and verify the home router has no port-forward,
UPnP, or DMZ rule targeting the host or VM. Tailscale supplements these controls; it does not
replace them.

## 4. Repeatable preflight

Before the VM exists, run the disposable production-derived boundary probe:

```powershell
.\scripts\run-network-boundary.ps1
```

On a Linux development host, use `./scripts/run-network-boundary.sh`. The runner creates random
temporary secrets outside the repository, bootstraps a fresh PostgreSQL volume, starts the actual
production Compose services, and verifies the following without printing secret values:

- the exact service/network allowlist, internal-only application/database networks, the offline
  key-rotation job, and the relay's exact `127.0.0.1:8000` publish;
- no host PostgreSQL or Docker-administration port;
- canonical proxy scheme/host handling, safe redirects, HSTS, and production errors;
- three valid and six ambiguous/malformed HTTP/1.1 request-framing cases, including a trailing
  request canary that must never produce a second response;
- UID/GID 10001, zero effective capabilities, no-new-privileges, a read-only root filesystem, and
  the bounded writable `/tmp` mount;
- only the runtime database identity and its three read-only secret mounts;
- required database connectivity, blocked Django-container egress, the relay's single live
  `web:8000` proxy destination, one shared non-root numeric
  secret-reader GID, exact 0700/0440 Linux ownership/modes, and absence of reusable secret values
  from container metadata, image history, and logs; and
- complete removal of the temporary containers, volumes, networks, and secret directory after
  success or failure.

After the real VM, policy, Serve proxy, UFW rules, and production services are ready, run from the
reviewed checkout:

```bash
sudo ./scripts/verify-private-ingress.sh \
  budget-host.example-tailnet.ts.net \
  household-budget \
  /etc/household-budget/secrets
```

The VM preflight re-runs the production runtime inspection and additionally checks Tailscale is
online under the exact tagged identity, Serve is HTTPS-only and Funnel-disabled, UFW is active and
limited to Tailscale TCP 22/443, the upstream listener is loopback-only, the certificate validates
for the hostname, TLS negotiates 1.2 or 1.3, HSTS is exact, and plain HTTP is either unreachable or
redirects to the exact HTTPS URL. It reads secret values only to compare them against local
metadata/history/log output, never prints them, and deletes its temporary status files. Run it only
from an authorized administrative session; retain a dated sanitized pass/fail summary, not its raw
status documents.

## 5. Required two-device release procedure

The automated preflights do not replace these bounded observations:

1. For `NET-01`, enroll a test device but leave it awaiting device approval. From that device,
   attempt only the exact VM hostname and ports 22, 443, 5432, 8000, 2375, and 2376. All connections
   and application name resolution must fail. Do not scan any other tailnet or LAN address.
2. Approve the device under the spouse role. For `NET-02`, confirm HTTPS 443 works after real
   password-plus-MFA login while SSH, PostgreSQL, upstream HTTP, and Docker ports remain denied.
3. Repeat from the administrator role. HTTPS and key-only SSH may work; ports 5432, 8000, 2375, and
   2376 must remain denied. Approval alone must not grant administrator access.
4. For `NET-03`, inspect the authenticated browser response and confirm the
   `__Host-budget_sessionid` cookie is `Secure`, `HttpOnly`, `SameSite=Strict`, has `Path=/`, and has
   no `Domain`. Confirm authenticated financial pages return `Cache-Control: no-store, private` and
   browser back/refresh does not reveal data after logout.
5. For `NET-04` and `NET-05`, repeat the documented exact-port and safe alternate-host/forwarded-
   header checks through the deployed proxy. Do not weaken the proxy or firewall to create a test.
6. For `NET-05`, perform the bounded HTTP/2 message-length mismatch check above and the HTTP/3
   equivalent if enabled. Record only protocol, expected rejection/reset, observed status, and pass
   or finding ID; do not retain the malformed request or private endpoint details.
7. Revoke the temporary device and confirm its existing browser/SSH connections and new connection
   attempts fail. Review only sanitized application, Tailscale, UFW, SSH, and Docker summaries.

Record the candidate commit, date, tester, device roles, expected/observed result, and any sanitized
finding IDs using `docs/ADVERSARIAL_TESTING.md`. Do not retain cookies, tailnet status JSON, internal
addresses, secret matches, raw financial responses, or broad scan output in Git.

## 6. Change and recovery rules

- Re-run both preflights after Compose, proxy, Tailscale policy, UFW, SSH, hostname, or secret-mount
  changes and before every release candidate.
- A changed Tailscale hostname requires updating both production hostname values together and a
  new VM preflight. Do not temporarily add the old name as an alias.
- If Serve or UFW verification fails, take the application out of service and restore the last
  reviewed policy; do not expose port 8000 as a workaround.
- Treat an unexpected Funnel flag, wildcard listener, Docker API listener, secret match, privileged
  database role, or unapproved-device connection as a release-blocking incident.
- Follow `docs/INCIDENT_RESPONSE.md` for containment and credential rotation. Follow
  `docs/BACKUP_AND_RESTORE.md` before any VM rebuild or data restore.
