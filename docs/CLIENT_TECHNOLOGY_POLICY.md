# Supported client technology policy

The Household Budget production client uses browser-native HTML, CSS, and JavaScript. It ships one
same-origin JavaScript file with no runtime package dependency and relies only on current platform
APIs exercised by the release browser matrix. The supported browser families are the Chromium,
Firefox, and WebKit engines pinned by the repository's Playwright lockfile. A browser version that
its vendor no longer supports is outside the product's support boundary and must be upgraded before
it is used for household financial data.

Legacy plug-in technologies are prohibited. Production templates and static assets may not contain
NSAPI-style plug-in elements, Flash or Shockwave, ActiveX, Silverlight, NaCl/PNaCl, Java applets,
plug-in enumeration APIs, or references to their executable artifact formats. The production
Content Security Policy independently sets `object-src 'none'`, so plug-in content cannot execute
even if an unsafe reference evades review.

`scripts/check_client_technologies.py` inventories every reviewed production template and static
root. It fails closed on a missing root, a symlink, a legacy artifact or reference, an unreviewed
file type, or an unexpectedly large text asset. Both local quality gates and pull-request CI run the
inventory. Adding a production client root, file type, framework, package, or privileged platform
API requires a security review, an explicit inventory-policy update, and coverage in all three
supported browser engines.

The cross-browser release workflow runs the authenticated product surface on desktop and narrow or
touch layouts in Chromium, Firefox, and WebKit. This matrix is compatibility evidence for current
browser-native technology; it does not extend support to obsolete browser releases or plug-in
runtimes.
