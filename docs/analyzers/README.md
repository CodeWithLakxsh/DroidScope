# Analyzers

Each analyzer declares the external tools it needs. When a tool is missing the
analyzer reports `unavailable` with the reason, and that reason reaches the
risk summary and every report — a scan never silently loses coverage.

| Analyzer | Profiles | Requires | Produces |
|---|---|---|---|
| `manifest-analyzer` | all | androguard | 14 structural rules over the manifest and network security config |
| `network-indicator-analyzer` | all | — | URLs, domains and addresses classified by routing scope |
| `resource-analyzer` | standard, full | apktool, java | Smali and decoded resources as a browsable artifact |
| `source-analyzer` | standard, full | jadx, java | Decompiled Java; hosts the source, secret and Firebase rule engines |
| `native-analyzer` | standard, full | pyelftools | ELF metadata, symbols, hardening; optional Ghidra summary |
| `yara-analyzer` | standard, full | yara-python | Content indicators from a validated rule set |

## The contract

```python
class Analyzer(ABC):
    name: str
    version: str
    required_capabilities: tuple[str, ...]
    profiles: tuple[ScanProfile, ...]

    async def check_prerequisites(self, data) -> tuple[bool, str | None]: ...
    async def analyze(self, data: AnalysisInput) -> AnalyzerResult: ...
```

`run()` wraps `analyze()` and converts a missing tool, a timeout or an
unexpected exception into a result with the corresponding status. An analyzer
that raises does not abort the scan; it produces a record of its own failure.

### Sharing work

Decompilation is the expensive step, so it happens once. The source analyzer
publishes the tree through `AnalysisInput.shared`, and the secret and Firebase
rule engines evaluate against the same index.

### Artifacts

Analyzers write large output to the artifact store and record a key. The API
exposes them by scan id and artifact kind, never by path:

| Kind | Produced by | Contents |
|---|---|---|
| `manifest` | manifest-analyzer | Decoded `AndroidManifest.xml` |
| `network-security-config` | manifest-analyzer | Decoded network security configuration |
| `decompiled-sources` | source-analyzer | JADX output, browsable |
| `source-tree-index` | source-analyzer | Precomputed file listing for the UI |
| `decoded-resources` | resource-analyzer | apktool output including smali |
| `native-analysis` | native-analyzer | ELF inspection results as JSON |
| `ghidra-analysis` | native-analyzer | Ghidra headless summary, when it ran |
| `yara-matches` | yara-analyzer | Matches with offsets |
| `network-indicators` | network-indicator-analyzer | Classified indicators |

## Writing a rule

See [writing-rules.md](writing-rules.md).
