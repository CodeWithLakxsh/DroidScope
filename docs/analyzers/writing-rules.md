# Writing detection rules

Two mechanisms, chosen by what the verdict depends on.

| | Declarative (YAML) | Structural (Python) |
|---|---|---|
| Lives in | `rules/<category>/*.yaml` | `backend/app/detection/rules/*.py` |
| Good for | Weaknesses visible in source text | Verdicts that depend on reasoning |
| Example | `Cipher.getInstance("AES/ECB/...")` | Whether an exported component is reachable |

If you find yourself encoding Android platform behaviour in a regular
expression, you want a structural rule.

---

## Declarative rules

### Full field reference

```yaml
rules:
  - id: DS-CRYPTO-042              # required, unique, DS-<CATEGORY>-<NNN>
    name: Short description         # required
    version: "1"                    # bump when behaviour changes
    category: cryptography          # required, a FindingCategory value
    severity: high                  # critical | high | medium | low | info
    confidence: medium              # high | medium | low
    engine: source-analyzer
    scope: code                     # code | java | kotlin | smali | resource | any

    description: >-                 # required: what was detected, factually
    impact: >-                      # required: what an attacker gains
    remediation: >-                 # required: what to do instead
    verification: >-                # optional: how to confirm it
    limitations: >-                 # optional: what detection cannot tell you

    cwe: ["CWE-327"]                # validated against CWE-\d+
    masvs: ["MASVS-CRYPTO-1"]       # validated against MASVS v2 identifiers
    references: [https://...]

    patterns:                       # required: any match triggers
      - 'MessageDigest\.getInstance\s*\(\s*"(?i:md5)"'
    require_all: []                 # every one must also appear in the file
    require_any: []                 # at least one must appear in the file
    exclude: []                     # suppress if matched on the same line
    exclude_file: []                # skip the file entirely if matched
    exclude_paths: ['/test/']       # path substrings to ignore
    include_third_party: false      # scan bundled libraries too

    confidence_rules:               # raise or lower confidence on extra signals
      - when_any: ['hashPassword']
        set: high
        scope: file                 # file | line
        reason: the digest is applied directly to a password

    max_findings: 60
    group_by: file                  # file | match
```

Everything is validated at load time. A malformed CWE identifier or an invalid
regular expression fails `droidscope rules validate`, so it cannot ship.

### Context is what makes a rule useful

Compare two ways of detecting MD5:

```yaml
# Noisy: fires on every MD5 call, including cache keys and ETags.
patterns: ['MessageDigest\.getInstance\s*\(\s*"MD5"\s*\)']
```

```yaml
# DS-CRYPTO-001: only where a credential is involved.
patterns: ['MessageDigest\.getInstance\s*\(\s*"(?i:md5)"']
require_any: ['(?i)(password|passwd|credential|token|pin|auth)']
exclude: ['(?i)(checksum|etag|cache[_ ]?key|file[_ ]?hash|integrity)']
confidence_rules:
  - when_any: ['(?i)(password|pwd)\s*\.?\s*(getBytes|toCharArray)']
    set: high
    reason: the MD5 call is applied directly to a password value
```

The second reports a real weakness; the first trains users to ignore the tool.
MD5 used for a non-security checksum is genuinely not a vulnerability —
`DS-CRYPTO-002` covers bare algorithm usage separately at `low` severity.

---

## Structural rules

Subclass `Rule`, declare `RuleMetadata`, implement `evaluate(context)`.

```python
class ExampleRule(Rule):
    meta = RuleMetadata(
        id="DS-MANIFEST-042",
        name="...",
        description="...",
        category=FindingCategory.component_security,
        severity=Severity.medium,
        confidence=Confidence.high,
        engine="manifest-analyzer",
        impact="...",
        remediation="...",
        cwe_ids=["CWE-926"],
        masvs_controls=["MASVS-PLATFORM-1"],
    )

    def evaluate(self, context: ManifestContext) -> Iterable[RawFinding]:
        for component in context.metadata.exported_components():
            if self._is_actually_safe(component, context):
                continue
            yield self.finding(
                title=f"...: {component.name}",
                affected_component=component.name,
                file_path=context.manifest_path,
                line_number=context.manifest_line_of(component.name),
                evidence=[
                    Evidence(
                        description="why this matters here",
                        snippet="<the relevant manifest fragment>",
                        kind="manifest",
                    )
                ],
            )

register(ExampleRule())
```

Contexts available: `ManifestContext`, `SourceContext`, `NativeContext`,
`IndicatorContext`.

### Evidence carries the argument

A finding's evidence should let a reviewer agree or disagree without opening
the APK. `DS-MANIFEST-001` attaches the component declaration, then adds an
evidence entry for each reason the configuration is dangerous — the attribute
was absent and the platform defaulted it; the guarding permission exists but is
`normal`, so any application can hold it. That is what turns "exported
component" from a label into an argument.

### Sensitive evidence

```python
Evidence(
    description="AWS access key id found",
    snippet=line_text,
    sensitive=True,
    raw_value=secret,     # masked at the persistence boundary
)
```

Normalisation stores `masked_snippet()` and a salted fingerprint. The plaintext
is never written to a column unless a deployment explicitly disables redaction.

---

## Testing: both directions, always

**A rule needs a test proving it fires on the vulnerable form and a test
proving it stays silent on the correct form.** Without the second, a rule is
indistinguishable from a keyword matcher.

1. Add the vulnerable form to `tests/fixtures/vulnerable-app/src/...`
2. Add the correct form to `tests/fixtures/secure-app/src/...`
3. Register the rule id in both parametrised lists in
   `backend/tests/integration/test_pipeline.py`
4. `make fixtures && make test-backend`

For fine-grained behaviour, unit test the rule directly — see
`tests/unit/test_manifest_rules.py`, which asserts that a signature-level
permission suppresses a finding and a `normal` permission does not.

---

## Calibration

| Severity | Use when |
|---|---|
| `critical` | Directly exploitable, serious consequence — a live credential, disabled TLS validation |
| `high` | A real weakness with a plausible attack path |
| `medium` | A weakness requiring particular conditions |
| `low` | Defence in depth, or worth reviewing |
| `info` | An observation with no impact by itself |

| Confidence | Use when |
|---|---|
| `high` | The evidence is conclusive on its own |
| `medium` | Reliable, but context could change the verdict |
| `low` | Heuristic; a reviewer must confirm |

A low-confidence critical is honest. A high-confidence rule that fires on
correct code is a bug.

## Checklist

- [ ] `id` unique, following `DS-<CATEGORY>-<NNN>`
- [ ] `impact` says what an attacker gains, not that something "is insecure"
- [ ] `remediation` is specific enough to act on
- [ ] CWE and MASVS identifiers are real (validation enforces the shape)
- [ ] `limitations` states what the detection cannot tell you
- [ ] Context excludes the obvious benign case
- [ ] A test proves it fires on the vulnerable fixture
- [ ] A test proves it stays silent on the secure fixture
- [ ] `droidscope rules validate` passes
