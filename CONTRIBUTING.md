# Contributing to DroidScope

Thank you for considering a contribution. Detection rules, analyzer
improvements and documentation fixes are all welcome.

## Ground rules

DroidScope's value rests on the trustworthiness of its output, so one rule
matters more than any style guide:

> **Never make the tool claim something it did not observe.**

In practice:

- an analyzer that could not run records *why*, and that reason reaches the
  risk summary and the report;
- a finding carries the evidence that produced it;
- a rule states its own limitations;
- no placeholder, sample or invented data appears in a code path that a user
  can reach. Fixtures belong in tests, clearly labelled as fixtures.

## Getting set up

```bash
make setup      # backend venv + frontend dependencies
make doctor     # see which external tools you have
make fixtures   # build the test APKs (needs the Android SDK)
make check      # lint, type check, validate rules, run tests
```

## Contributing a detection rule

This is the most valuable contribution, and it has the strictest requirement.

**Every rule needs two tests: one proving it fires on the vulnerable form, and
one proving it stays silent on the correct form.** A rule with only the first
test is indistinguishable from a keyword matcher, and keyword matchers are why
people stop trusting scanners.

### 1. Choose the right kind of rule

| Use | When |
|---|---|
| **Declarative YAML** in `rules/<category>/` | The weakness is visible in source text, even with surrounding context |
| **Structural Python** in `backend/app/detection/rules/` | The verdict depends on reasoning — platform versions, permission protection levels, relationships between declarations |

If you find yourself encoding platform behaviour in a regular expression, you
want a structural rule.

### 2. Write it

A YAML rule looks like this:

```yaml
- id: DS-CRYPTO-042
  name: Short, specific description of the weakness
  version: "1"
  category: cryptography
  severity: high
  confidence: medium
  engine: source-analyzer
  scope: code
  description: >-
    What was detected, factually.
  impact: >-
    What an attacker gains, concretely. Not "this is insecure".
  remediation: >-
    What to do instead, specifically enough to act on.
  cwe: ["CWE-327"]
  masvs: ["MASVS-CRYPTO-1"]
  references:
    - https://mas.owasp.org/MASTG/tests/android/...
  limitations: >-
    What this detection cannot tell you.
  patterns:
    - 'DangerousApi\.call\s*\('
  require_any:        # context that must also be present
    - '(?i)(password|token)'
  exclude:            # suppress on the matched line
    - '(?i)(test|example)'
  exclude_paths:
    - /test/
```

Fields are validated at load time. CWE identifiers must match `CWE-\d+` and
MASVS controls must be real v2 control identifiers — `droidscope rules validate`
fails otherwise, so a typo cannot ship.

### 3. Prove it both ways

Add the vulnerable form to `tests/fixtures/vulnerable-app/` and the correct
form to `tests/fixtures/secure-app/`, then extend the parametrised lists in
`backend/tests/integration/test_pipeline.py`:

```python
# in TestVulnerableFixture.test_expected_source_rules_fire
"DS-CRYPTO-042",

# in TestSecureFixture.test_rules_do_not_fire_on_correct_code
"DS-CRYPTO-042",
```

Then:

```bash
make fixtures
make test-backend
```

### 4. Calibrate severity and confidence honestly

| Severity | Meaning |
|---|---|
| `critical` | Directly exploitable with serious consequences — a live credential, broken TLS validation |
| `high` | A real weakness with a plausible attack path |
| `medium` | A weakness requiring particular conditions |
| `low` | Weakness in depth, or a configuration worth reviewing |
| `info` | An observation with no impact by itself |

| Confidence | Meaning |
|---|---|
| `high` | The evidence is conclusive on its own |
| `medium` | Reliable, but context could change the verdict |
| `low` | Heuristic; a reviewer must confirm |

A `low`-confidence `critical` is fine and honest. A `high`-confidence rule that
fires on correct code is a bug.

## Code style

**Python.** Ruff handles formatting and linting (`make format`). Type hints on
public functions. Comments should explain *why*, not restate the code — the
existing comments that explain Android platform behaviour or a non-obvious
security decision are the model.

**TypeScript.** `npx tsc -b --noEmit` must pass. Severity and status must never
be conveyed by colour alone: pair them with a glyph and a text label. Keyboard
focus styles are never removed.

## Pull requests

1. Branch from `main`.
2. Make sure `make check` passes.
3. Describe what changed and why. For a rule, include an example of the code it
   fires on and the code it must not fire on.
4. Never commit an APK, a credential, or a real sample. The fixtures are built
   from source for exactly this reason.

## Reporting a bug

Include the DroidScope version, `droidscope doctor` output, what you expected,
and what happened. For a false positive or negative, the smallest code snippet
that reproduces it is worth more than anything else.

Security vulnerabilities in DroidScope itself go through
[SECURITY.md](SECURITY.md), not the public issue tracker.

## Code of conduct

This project follows the [Contributor Covenant](CODE_OF_CONDUCT.md).
