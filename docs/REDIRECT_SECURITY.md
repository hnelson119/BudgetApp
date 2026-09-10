# Redirect security policy

Status: implemented; release-candidate verification pending  
Last reviewed: 2026-09-10

## Boundary

Automatic redirects use relative application paths or an absolute URL on the current request
authority. The response boundary rejects malformed locations, backslash variants, user-info URLs,
unsupported schemes, HTTPS-to-HTTP downgrades, and destinations on an unapproved authority.

An external destination is permitted only when its exact authority appears in
`EXTERNAL_REDIRECT_ALLOWED_HOSTS` and the redirect uses an explicit HTTPS URL. Scheme-relative
external URLs are rejected. Ports, when required, are part of the exact allowlist entry.

The private production deployment has no business need for automatic external redirects and
requires the external allowlist to remain empty during settings loading. Existing login and MFA
return targets are independently restricted to the current host, while notification actions accept
only internal application paths. A rejected response becomes an empty, non-cacheable HTTP 400
response without a `Location` header.

Any future external redirect requires a documented owner and purpose, an exact HTTPS authority,
focused allowlist and rejection tests, the full quality gate, and release-candidate verification.
