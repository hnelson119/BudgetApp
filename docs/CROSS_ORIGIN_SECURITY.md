# Cross-origin response policy

The Household Budget application is private and same-origin. It has no cross-origin API client,
public embeddable resource, CDN, or browser integration, so no response needs to grant Cross-Origin
Resource Sharing access. Production accepts one exact private HTTPS hostname and one matching CSRF
trusted origin.

`SameOriginResponseBoundaryMiddleware` is outside the application response stack and outside
WhiteNoise in hardened deployments. It removes every CORS permission field, including credentials,
methods, headers, origin, private-network access, exposed headers, and cache lifetime. It also
removes `Timing-Allow-Origin` and sets `Cross-Origin-Resource-Policy: same-origin`. An untrusted
`Origin` value therefore cannot influence response metadata, and a view, error handler, redirect,
or static-file configuration cannot accidentally grant a wildcard or reflected origin.

WhiteNoise independently keeps `WHITENOISE_ALLOW_ALL_ORIGINS = False`. This closes the permissive
static-asset default recorded and retested as `M10-F002`, while the outer response boundary protects
all other response classes and remains effective if the static implementation changes.

Any future cross-origin consumer requires an explicit architecture and security review before this
boundary changes. The review must define exact origins, resources, methods, headers, credential
behavior, cache behavior, and tests proving that sensitive responses are not exposed. Wildcard or
request-reflected origins remain prohibited.
