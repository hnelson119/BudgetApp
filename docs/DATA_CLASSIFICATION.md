# Sensitive-data classification and protection requirements

Status: implemented; deployment verification pending
Last reviewed: 2026-09-13
Next scheduled review: 2026-12-12

The authoritative catalog is `docs/data-classification.json`. It classifies every stored Django
model and the non-database surfaces that create or process application data. The quality gate
compares the catalog with Django's live model registry, so a newly installed model fails validation
until it receives a protection level and handling record.

## Protection levels

| Level | Intended data | Minimum handling boundary |
| --- | --- | --- |
| Restricted | Authentication material, cryptographic material, detailed financial records, raw imports, exports, backups, and audit payloads | Exact authenticated encryption in transit, encrypted host storage, encrypted backups, strongest household and service separation, no sensitive logging or client persistence, and dataset-specific disposal. |
| Confidential | Household identity, membership, security-event, notification, and pseudonymous operational data | Encrypted transit and host storage, household or administrator least privilege, minimized and redacted logging, bounded retention, and no unmanaged copies. |
| Internal | Authorization schema, dependencies, synthetic tests, release evidence, and coarse health metadata | Access-controlled source, CI, database, or host storage; authenticated transport; integrity review; and no live household or reusable credential values. |
| Public | Intentionally distributable static assets with no household, identity, financial, security-sensitive, or deployment-specific values | Reviewed release integrity and explicit declassification; modification remains controlled even when reading is allowed. |

Each level defines requirements for encryption in transit and at rest, database-level encryption,
integrity, retention, logging, access to logs, access control, privacy, confidentiality, encoding,
disposal, backups, and client storage. Dataset records then apply concrete lifecycles and evidence.

Encoding never changes a protection level by itself. Base64, URL encoding, compression, password
hashing, keyed pseudonyms, partial account numbers, masks, ciphertext, signed session data, QR
payloads, and other reversible or linkable derivatives inherit their source classification unless
an explicit irreversible declassification review proves otherwise.

## Classified datasets

| Level | Dataset |
| --- | --- |
| Restricted | Authentication, MFA, recovery, throttling, and sessions |
| Restricted | Household financial planning, ledger, debts, goals, reserves, notifications, and raw import staging |
| Restricted | Protected audit history, signed checkpoints, and framework administration history |
| Restricted | Transient request, upload, form, template, and response memory |
| Restricted | Approved-browser cookies, authenticated DOM, and session surfaces |
| Restricted | Generated financial and audit CSV downloads |
| Restricted | Deployment secrets, private keys, certificates, and service credentials |
| Restricted | Encrypted backups, restore streams, and recovery copies |
| Confidential | Household profile and membership data |
| Confidential | Security and operational logs across the inventoried stack |
| Internal | Framework authorization and content-type schema |
| Internal | Source, CI, scan, test, and release evidence |
| Internal | Offline breached-password reference corpus |
| Internal | Release, readiness, backup-freshness, and service-health metadata |
| Public | Intentionally public CSS and dependency-free JavaScript assets |

The machine catalog assigns all 45 current database models exactly once. A model is classified at
the highest protection needed for any of its fields, so adding a field to an existing model cannot
lower its controls. The model registry check catches new models; the mandatory review trigger for
any model or field change catches classification, lifecycle, or retention changes within an
existing model.

The quality gate also pins the rank of each protection level and a minimum level for every
dataset. Moving a model between datasets cannot bypass its independent minimum: models default
to Restricted, with reviewed exceptions only for framework authorization schema (Internal) and
household profiles and membership (Confidential). Stronger classifications are accepted. Lowering
a minimum requires an explicit policy-code review; editing the catalog alone fails the gate.
This guards classification changes, not the live enforcement of every handling requirement.

## Privacy and regulatory boundary

The current context is a private, self-hosted application for one invited household. It has no
public registration, bank synchronization, payment processing, credit reporting, behavioral
analytics, advertising, sale of data, or third-party authentication, mail, storage, or telemetry
integration. The household remains the deployment and data custodian except for the infrastructure
providers named in the communication and logging inventories.

This engineering classification does not declare that a law or regulatory regime is inapplicable.
Before deployment, the release owner must record the jurisdiction and confirm privacy,
breach-notification, financial-data, tax-record, household, and provider-contract obligations. The
documented baseline—minimization, purpose limitation, household-scoped access, protected transport
and storage, bounded retention, controlled export, incident handling, and verified disposal—applies
even when no named regulatory regime is triggered.

Reassess before public or commercial use; use by another household, employer, minor, healthcare or
regulated professional; a new jurisdiction or data-residency boundary; or any bank, payment,
credit, tax, identity-provider, analytics, telemetry, messaging, or cloud-storage integration.

Authenticated members can review and correct current records and create protected financial and
audit exports. A request not supported in the product is handled by the release owner through a
verified offline process that accounts for encrypted backups, append-only audit history, legal or
incident holds, and session revocation. The product never silently rewrites audit history or claims
erasure while a retained backup remains live.

## Current implementation and release boundary

Repository controls already enforce private authenticated HTTPS, purpose-separated mutual TLS,
server-side sessions, MFA seed encryption, password and recovery hashing, encrypted Restic backups,
signed audit checkpoints, household-scoped access, redacted isolated security logging, no-store
sensitive responses, browser cleanup, response-only exports, and automatic raw-import scrubbing
after 24 hours by default (never configured beyond 720 hours).

The selected production VM must also place PostgreSQL and other confidential host data on an
encrypted volume with separately protected recovery material. That is a mandatory protection-level
requirement, but its dated release-machine observation is deliberately not claimed here. ASVS
`v5.0.0-14.2.4` remains partial until the live release evidence confirms the documented controls,
including database-volume encryption, effective retention, access, disposal, and recovery.

## Review and verification

Review the inventory at least every 90 days, for every release candidate, and whenever a data
surface, control, retention rule, integration, deployment context, privacy request, finding, or
incident changes. Do not put example secrets, private hostnames, live identities, or financial
values in the catalog.

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_data_classification.py
.\.venv\Scripts\python.exe -m pytest tests\test_data_classification.py
```

The validator checks schema completeness, review cadence, privacy reassessment triggers, all four
protection levels, all 15 datasets, evidence paths, the exact 45-model registry, cookie and session
requirements, secure database transport, browser cleanup, no-store exports, staged-import
scrubbing, and encrypted-backup retention. It implements the repository-deliverable documentation
for ASVS `v5.0.0-14.1.1` and `v5.0.0-14.1.2` without claiming the separate live implementation
verification.
