# Regular-expression safety

Status: implemented; release verification pending
Last reviewed: 2026-09-17

## Boundary

Production regular expressions are code-owned validation and parsing rules. Request, account,
household, import, financial, and other runtime values must never become regular-expression syntax.
Callers pass untrusted values only as the candidate text matched against a reviewed expression.

The only runtime-built production expression belongs to the context-specific password validator.
It converts configured product identifiers to normalized alphanumeric skeletons, applies
`re.escape` independently to every alternative, joins only those escaped alternatives, and then
places that completed fragment into a fixed anchored expression. The expression is compiled once
when the validator is constructed. No request value participates in its construction.

## Enforced rules

`scripts/check_regex_safety.py` parses every non-migration Python file in all 14 production
application roots and rejects recognized direct API calls unless:

- calls to Python's regular-expression execution functions use a non-empty literal string or byte
  pattern;
- Django `RegexField` and `RegexValidator` constructors receive a non-empty literal pattern;
- the single reviewed password-validator expression uses exactly one interpolated alternatives
  fragment built by applying `re.escape` to each value;
- the standard `re` module and Django regex constructors are not imported under aliases, `re`
  symbols are not imported directly, and the third-party `regex` engine is not imported.

New dynamic patterns, new construction forms, and unescaped interpolation fail both local and CI
quality gates. If a future feature truly requires a runtime pattern, its grammar, maximum size,
escaping or allowlist rules, complexity bound, and adversarial tests must be reviewed before the
checker is changed. Escaping prevents injection; it does not by itself prevent catastrophic
backtracking in a newly introduced code-owned expression. This is an inventory of reviewed direct
APIs, not whole-program data-flow analysis: arbitrary callable reassignment, reflection, custom
engines, or dynamically loaded code still require source review. The escaped-alternatives exception
rejects reassignment and format-spec interpolation rather than assuming a matching variable name
is evidence of safe construction.

## Verification

Run:

```powershell
.\.venv\Scripts\python.exe scripts\check_regex_safety.py
.\.venv\Scripts\python.exe -m pytest tests\test_regex_safety.py tests\test_password_policy.py
```

The tests accept the production inventory and the reviewed escaped-alternatives construction, then
prove that dynamic Python patterns, dynamic Django patterns, and an unescaped password alternative
are rejected. This implements the repository-deliverable portion of ASVS `v5.0.0-1.2.9`; a dated
release-candidate run remains pending.
