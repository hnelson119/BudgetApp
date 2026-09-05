# Software bill of materials and trusted-source policy

Status: maintained source/build inventory and CI image inventories implemented; release-candidate
verification pending
Last updated: 2026-09-05

## Scope

`docs/sbom.cdx.json` is the canonical, deterministic CycloneDX 1.6 inventory for third-party
software selected by this repository. It currently contains 83 components:

- 61 locked Python packages, with production and development scope distinguished;
- 6 locked npm packages with their registry resolution and SHA-512 integrity values;
- 8 digest-pinned container images used by production, builds, CI, browser tests, or security tests;
- 4 version-pinned Go modules compiled into the backup image;
- the version- and checksum-pinned Restic source archive; and
- 3 GitHub Actions pinned to complete commit identifiers.

The inventory includes production, development, build, test, and CI inputs because each can affect
the delivered application or the evidence used to approve it. Each component records its package
URL, exact selected version or revision, source file, use scope, and approved source repository.
Available npm licenses and integrity hashes, container digests, and the Restic source digest are
also retained. A content fingerprint and deterministic UUID change whenever the inventory changes.

The checked-in inventory does not claim to know the operating-system packages selected when
`apk upgrade` runs. GitHub Actions therefore builds the three release images, scans them, generates
a CycloneDX SBOM from each resulting image with the same immutable Trivy image, and uploads the
three files as a 90-day `release-image-sboms-<commit>` artifact. Those image-resolved inventories
cover installed Alpine, Python, and embedded executable components that a source-only catalog
cannot reliably predict.

Together, the maintained repository inventory and image-resolved artifacts implement the
repository-deliverable portion of ASVS `v5.0.0-15.1.2`. They do not mark a future release candidate
verified. A release owner must retain the exact candidate's artifact and review its components and
vulnerability results before approval.

## Approved repositories

New components may come only from this reviewed source set:

| Ecosystem | Approved source | Enforcement |
| --- | --- | --- |
| Python | `pypi.org` / `https://pypi.org/simple` | Exact lock versions; CI and release-image installs set the index explicitly; weekly Dependabot and `pip-audit` review |
| npm | `registry.npmjs.org` | Lockfile v3 resolution URLs and SHA-512 integrity required; browser build sets the registry explicitly; weekly Dependabot and npm audit |
| OCI images | Docker Hub (`docker.io`) and Microsoft Container Registry (`mcr.microsoft.com`) | Every referenced image is pinned by SHA-256 digest; Dependabot reviews Docker updates |
| Go modules | `proxy.golang.org` with `sum.golang.org` verification | Backup build disables direct fallback and pins every explicitly upgraded module version |
| Restic source | `github.com/restic/restic` | Fixed release URL plus required SHA-256 checksum before extraction |
| GitHub Actions | `github.com` | GitHub-owned actions only, pinned to full commit identifiers, with weekly Dependabot review |

The SBOM validator fails if the effective repository set changes. A new package registry, image
registry, action owner, direct Go fallback, mutable action reference, unresolved npm package, or
unhashed container/source input requires an explicit supply-chain review before merge. Mirror or
private-registry adoption must document ownership, upstream synchronization, authentication,
availability, malware response, and package-confusion controls before it replaces this allowlist.

Repository approval is not proof that an individual version is safe. Dependency audit, npm audit,
container vulnerability scanning, review of maintainer/project health, and normal code review remain
separate gates. A package that is abandoned, unexpectedly transferred, typosquatted, or inconsistent
with the expected project must not be accepted merely because it is hosted by an approved service.

## Updating the inventory

1. Change only the authoritative source: Python locks, npm lock, Docker/Compose image pins, Restic
   and Go build pins, or immutable workflow action pins.
2. Run `python scripts/build_sbom.py`. Never hand-edit `docs/sbom.cdx.json`.
3. Review the SBOM diff. Confirm the component name, version, scope, package URL, source repository,
   source file, and available digest/license data match the reviewed dependency change. An
   unexplained addition, removal, downgrade, registry change, or new duplicate is a finding.
4. Run `python scripts/check_sbom.py`, the Python and npm audits relevant to the change, and the full
   local quality gate. The checker rebuilds the complete catalog from source and requires byte-data
   equivalence after JSON parsing.
5. Let GitHub build and scan all three release images. Confirm the SBOM upload step succeeds and the
   artifact name contains the tested commit SHA. Review the image job rather than treating upload
   success as a vulnerability pass.
6. Merge through a reviewed pull request. Dependabot proposals never deploy automatically.

The builder intentionally fails closed on non-exact Python requirements, conflicting Python
versions, npm entries without the official HTTPS registry and SHA-512 integrity, unpinned workflow
actions, missing Restic pins, duplicate package references, and changes to the approved repository
set. Image pins remain subject to the existing deployment tests and secret scan as defense in
depth.

## Release evidence and retention

For every release candidate, record the candidate commit, GitHub run URL/identifier, artifact name,
creation time, expiration time, and SHA-256 digest of each downloaded image SBOM. Before the 90-day
GitHub retention window expires, copy the three candidate SBOMs to the access-controlled release
evidence archive when the product or incident-retention policy requires a longer record. Keep that
archive outside the application VM and restrict it to the release/security owner.

Compare the checked-in SBOM to each image-resolved SBOM and investigate missing production Python
packages, unexpected installed packages, unrecognized operating-system repositories, duplicate or
shadowed packages, and components without useful identity/version data. The source SBOM remains in
Git history; generated image SBOMs bind to the immutable candidate build and must not be replaced by
an artifact from a later commit.

SBOMs should contain identifiers and versions, not credentials or household data. Even so, treat
unreleased component inventories as internal security information. Do not attach raw scanner
diagnostics, registry credentials, private hostnames, Docker configuration, filesystem contents, or
real deployment metadata. Record findings through the sanitized security-finding process.

If an artifact is missing, expired before preservation, generated for a different commit, or cannot
be matched to all three release images, the SBOM release gate is not verified and the images must be
rebuilt and reassessed.
