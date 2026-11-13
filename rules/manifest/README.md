# Manifest rules

Manifest findings are produced by **structural Python rules**, not by the YAML
pattern engine, because the verdict depends on platform behaviour rather than on
text matching. Deciding whether an exported component is reachable requires
reasoning over the component kind, the declared `android:exported` value, the
effective `targetSdkVersion`, the protection level of any guarding permission
and the component's intent filters — logic that a regular expression cannot
express correctly.

Those rules live in
[`backend/app/detection/rules/manifest_rules.py`](../../backend/app/detection/rules/manifest_rules.py)
and are covered by unit tests in `backend/tests/unit/test_manifest_rules.py`.

| Rule | Subject |
|------|---------|
| `DS-MANIFEST-001` | Exported component without access control |
| `DS-MANIFEST-002` | Exported content provider exposing application data |
| `DS-MANIFEST-003` | `android:debuggable` enabled |
| `DS-MANIFEST-004` | Backup enabled (explicit or by platform default) |
| `DS-MANIFEST-005` | Cleartext traffic permitted, resolved against the network security config |
| `DS-MANIFEST-006` | User-installed CAs trusted outside `debug-overrides` |
| `DS-MANIFEST-007` | Custom permission with a weak protection level |
| `DS-MANIFEST-008` | Permission combinations enabling broad data collection |
| `DS-MANIFEST-009` | Browsable deep link without App Links verification |
| `DS-MANIFEST-010` | Task-hijacking preconditions |
| `DS-MANIFEST-011` | `android:sharedUserId` declared |
| `DS-MANIFEST-012` | Outdated `minSdkVersion` / `targetSdkVersion` |
| `DS-MANIFEST-013` | Weak signing certificate or v1-only signature |
| `DS-MANIFEST-014` | `android:testOnly` build |

To add a pattern-based rule for a *resource* file (anything under `res/`), use
this directory with `scope: resource`; see
[`docs/analyzers/writing-rules.md`](../../docs/analyzers/writing-rules.md).
