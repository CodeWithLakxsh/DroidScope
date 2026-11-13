# Architecture decisions

Decisions that shaped DroidScope, with the reasoning and the alternatives that
were rejected. The format is deliberately short: context, decision, consequence.

---

## ADR-001: Analyzers return results; they never raise for expected conditions

**Context.** An analysis run involves several third-party tools, any of which
may be missing, slow, or killed by a crafted input. The obvious design — let
failures propagate — produces a scan that either succeeds completely or fails
completely.

**Decision.** `Analyzer.run()` converts a missing tool, a timeout, or an
unexpected exception into an `AnalyzerResult` with a status (`unavailable`,
`timed_out`, `failed`) and a reason. The pipeline records every execution,
including the ones that produced nothing.

**Consequence.** A scan with JADX missing still returns manifest findings, and
the result says exactly what was not covered. That record flows into the risk
summary's coverage section and into every report. The alternative — silently
producing fewer findings — would make an incomplete scan indistinguishable from
a clean one, which is the single most dangerous failure mode for a security
tool.

---

## ADR-002: Two kinds of rule, chosen by what the verdict depends on

**Context.** Most findings are expressible as "this pattern appears in source".
Some are not: whether an exported component is a vulnerability depends on the
component kind, the target SDK, the protection level of any guarding
permission, and whether an intent filter is present.

**Decision.** Pattern rules are declarative YAML with required and excluded
context. Structural rules are Python that reasons over parsed models.

**Consequence.** Rule authors who are not Python developers can contribute
pattern rules. The rules that need platform knowledge get to express it
properly instead of encoding it in an unreadable regular expression. The cost
is two mechanisms to learn; `CONTRIBUTING.md` gives a one-line test for which
to use.

---

## ADR-003: Finding fingerprints exclude line numbers

**Context.** Comparing two APK versions requires deciding whether a finding in
the new version is the same issue as one in the old.

**Decision.** A finding's fingerprint hashes the rule id, affected component,
file path and evidence value fingerprints — **not** the line number.

**Consequence.** Inserting a line above a vulnerable call does not present the
unchanged issue as newly introduced. The cost is that two genuinely distinct
instances of the same rule in the same file with identical evidence collapse
into one. That trade-off favours the diff being trustworthy.

---

## ADR-004: Secrets are masked at the persistence boundary

**Context.** The secret detector necessarily handles plaintext credentials. If
they reach the database, DroidScope becomes a credential store, and its backups
and reports become a liability.

**Decision.** `Evidence` carries `raw_value` in memory only. Normalisation
stores `masked_snippet()` plus a salted, non-reversible fingerprint. The
plaintext is persisted only when a deployment explicitly disables redaction.

**Consequence.** A reviewer sees `"AKIA••••••••••••••BK"` and can correlate the
same secret across scans through the fingerprint, without DroidScope holding
the credential. Verifying the actual value requires going back to the APK,
which is the right amount of friction.

---

## ADR-005: A database-backed job queue, not Redis or Celery

**Context.** Decompilation must not run in an HTTP handler. That needs a queue.

**Decision.** A `jobs` table with atomic claiming via a conditional `UPDATE`,
heartbeats and stale-lock recovery. Redis is optional and only a wake-up
signal; the database remains the source of truth.

**Consequence.** `make dev` needs no broker, and local development matches
production semantics. Claiming is correct without row locks, so it behaves the
same on SQLite and PostgreSQL. The cost is polling latency, bounded by
`worker_poll_interval_seconds` (1 s by default), which is irrelevant next to
decompilation time. Celery was rejected as a large dependency whose failure
modes are harder to reason about than a single table.

---

## ADR-006: The risk score is explicitly not CVSS

**Context.** Users expect a single number. CVSS is the familiar one, but CVSS
scores a specific vulnerability against a defined metric vector, which nothing
in a static scan performs.

**Decision.** Produce a *DroidScope risk summary*: a weighted sum of
severity × confidence × review status, mapped through a saturating curve, with
a severity floor so one critical finding cannot be averaged away. The method
string says "not a CVSS score", and a unit test asserts it.

**Consequence.** The number is honest about what it is, and the arithmetic is
published alongside it so a reader can check it. Calling it CVSS would have
been more marketable and less true.

---

## ADR-007: Extracted network indicators are never contacted

**Context.** Resolving an extracted domain would let DroidScope say whether it
is live, and probing an endpoint would improve accuracy.

**Decision.** Indicators are extracted, classified by routing scope, and
reported as observations. No DNS resolution, no connection, no scanning. The UI
and reports say so explicitly.

**Consequence.** DroidScope cannot be used — accidentally or deliberately — to
scan infrastructure from an analyst's machine, and analysing a malware sample
does not notify its operator that the sample was analysed. Classification by
scope recovers most of the analytical value: a private address in a release
build is interesting whether or not it answers.

---

## ADR-008: No security-control bypass modules in dynamic analysis

**Context.** Frida is routinely used for SSL unpinning and root-detection
bypass, and a mobile security tool is expected to offer them.

**Decision.** Ship observational modules only. No unpinning, no root-detection
bypass, no biometric bypass. The code comments and the API response state this.

**Consequence.** Some legitimate testing is out of scope, and testers will use
Frida directly for it. In exchange, DroidScope cannot be deployed as an
off-the-shelf control-defeat toolkit, and the dynamic subsystem's output is
always "what the application did", never "what it did once we broke something".
Such modules, if ever added, belong behind a separate explicit opt-in.

---

## ADR-009: Storage is content-addressed; uploaded filenames are display-only

**Context.** An uploaded filename is attacker-controlled and historically a
reliable source of path traversal.

**Decision.** Objects are stored at `apks/<aa>/<sha256>.apk`. The sanitised
original filename is kept as metadata for display. Every storage key is
validated segment by segment, and every resolved path is re-checked against the
store root.

**Consequence.** A filename cannot influence a path, deduplication is free (the
same bytes have the same key), and the file-browsing API has a second
independent check after path resolution.

---

## ADR-010: One report document, several renderers

**Context.** Four output formats are required. Rendering each from the database
independently guarantees they will eventually disagree.

**Decision.** `build_report_document()` produces one canonical dictionary. PDF,
HTML, JSON and SARIF renderers consume it.

**Consequence.** A field added to the document appears everywhere. The JSON
export *is* the document, so what a user reads in the PDF is exactly what
tooling consumes. Format-specific concerns stay in the renderers: escaping for
ReportLab's mini-HTML parser, autoescaping plus CSP for HTML, and SARIF's fixed
level vocabulary with the original severity preserved in properties.

---

## ADR-011: A custom SQLAlchemy type for enum columns

**Context.** Enum columns stored as `String` come back as plain `str`, so
`row.severity.value` works on a freshly constructed object and raises on a
loaded one. This produced a real bug that only appeared in the report path.

**Decision.** `StrEnumType`, a `TypeDecorator` that validates on write and
coerces back to the enum on read. The column stays a `VARCHAR`.

**Consequence.** The whole class of bug disappeared rather than being patched
at each call site. Alembic renders the column as `sa.String(length=n)` through
a `render_item` hook, so migrations do not import application code.

---

## ADR-012: Tool paths come from the environment, never from the API

**Context.** A settings page that configures tool locations is convenient.

**Decision.** Tool paths are read from environment variables at startup and
validated as existing executables. The settings endpoint exposes tool
*availability* as booleans and refuses to set a path.

**Consequence.** An authenticated API user cannot turn the settings endpoint
into arbitrary command execution by pointing `jadx_path` at a script they
control. Changing a tool location requires access to the deployment
environment, which is the correct privilege boundary.

---

## ADR-013: Fixtures are built from source, not committed as binaries

**Context.** Testing an APK analyser requires APKs. Committing them is the easy
path.

**Decision.** Two Android applications live in `tests/fixtures/` as source, and
`scripts/development/build_fixture_apk.sh` builds signed APKs with the Android
SDK directly — aapt2, javac, d8, zipalign, apksigner, no Gradle. The signing
key is generated at build time and is not committed. `.gitignore` excludes
`*.apk`.

**Consequence.** The repository contains no binaries and no key material, the
fixtures are reviewable as source, and a reviewer can see exactly which line
each test expects to trigger. The cost is that fixture tests skip when the
Android SDK is absent, which they report rather than silently passing.

---

## ADR-014: The secure fixture is a first-class test artifact

**Context.** A test suite that only proves rules fire on bad code cannot
distinguish detection from keyword matching.

**Decision.** A second application, `secure-app`, implements the same
functionality correctly — AES-GCM instead of ECB, bound parameters instead of
concatenation, signature permissions instead of none. Fifteen rules are
asserted **not** to fire on it.

**Consequence.** Every new rule must pass both directions, which is enforced in
`CONTRIBUTING.md`. This caught a real design question during development: the
secure app's App Link handler *is* exported, and the rule correctly reports it
at low severity. The test was wrong; the rule was right.
