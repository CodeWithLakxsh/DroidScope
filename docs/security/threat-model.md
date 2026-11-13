# Threat model

DroidScope's defining characteristic is that **its input is hostile by
definition**. Users submit APKs they do not trust — that is the point of the
tool — and those files are handed to several third-party parsers.

## Assets

| Asset | Why it matters |
|---|---|
| The analysis host | Compromise through a crafted APK would be the worst outcome |
| Uploaded APKs | May be proprietary, unreleased, or live malware |
| Decompiled source trees | The application's full source, including any secrets in it |
| Detected credentials | The tool necessarily handles plaintext secrets |
| Analysis results | Disclose an organisation's unfixed vulnerabilities |

## Adversaries

1. **A crafted APK.** The primary adversary. Reaches archive handling, XML
   parsing, DEX parsing, ELF parsing and the external tools.
2. **A malicious API client.** On a shared deployment, someone who can reach
   the API but should not reach everything behind it.
3. **A hostile report consumer.** Content from an APK is embedded in reports;
   those reports are opened by other people.

---

## Threat 1: the uploaded APK

### Archive attacks

| Attack | Control |
|---|---|
| Zip bomb (per entry) | Entries over 16 MB uncompressed with a ratio above 200:1 are rejected |
| Zip bomb (cumulative) | Total uncompressed size is capped at 4 GB by default |
| Entry flooding | Entry count capped at 60,000 |
| Path traversal | Entry names rejected for `..`, absolute paths, backslashes and NUL |
| Symlink extraction | Symlink entries (`S_IFLNK` in external attributes) are refused |
| Parser-confusing compression | Only `stored` and `deflate` are accepted |
| Duplicate entry confusion | Duplicates are detected and surfaced as a warning |
| Non-APK upload | Requires `AndroidManifest.xml`, code, and real DEX magic |

Extraction re-validates: each destination is resolved and re-checked against
the extraction root, so a name that passes the first check still cannot escape.

### Parser exploitation

Analysis runs in a **separate worker process** from the API, under a timeout
that kills the entire process group. In the supplied Docker deployment the
worker has a read-only root filesystem, all capabilities dropped,
`no-new-privileges`, a memory limit and a tmpfs for scratch. A parser crash
loses one scan; a parser exploit lands in the most constrained process.

### Command injection

Every subprocess is an argument vector. **No code path invokes a shell**, so a
package name containing `; rm -rf /` is just a string. Child environments are
minimal and proxy variables are stripped, so static analysis cannot be induced
to make a network request.

### Execution

**An uploaded APK is never executed on the analysis host.** Dynamic analysis
installs and runs applications on a *device*, is disabled by default, and
requires explicit per-session authorisation.

---

## Threat 2: the API client

| Threat | Control |
|---|---|
| Unauthenticated access | Optional API key via `DROIDSCOPE_REQUIRE_AUTH`; constant-time comparison |
| Command execution via settings | Tool paths come from the environment only and cannot be set through the API ([ADR-012](../ARCHITECTURE_DECISIONS.md)) |
| Path traversal through file browsing | Storage keys validated segment by segment; resolved paths re-checked against the artifact root |
| Host filesystem disclosure | Responses carry no absolute paths; the capabilities schema omits tool paths entirely |
| Resource exhaustion | Upload size cap, analyzer timeouts, bounded worker concurrency |
| Information disclosure through errors | The catch-all handler returns a generic message; details go to the server log |

**Not addressed:** DroidScope has no multi-user model. A single shared API key
grants access to everything. Deployments needing per-user isolation must
enforce it in front of the API.

---

## Threat 3: the report consumer

A report embeds strings taken from the analysed APK, so a crafted APK is an
injection vector against whoever reads the report.

| Threat | Control |
|---|---|
| XSS in the HTML report | Jinja autoescaping on every value; no raw interpolation |
| Script execution in a rendered report | Restrictive CSP meta tag: `default-src 'none'` |
| Markup injection in the PDF | APK-derived text is escaped before ReportLab's mini-HTML parser sees it |
| Content sniffing on download | `X-Content-Type-Options: nosniff` and a CSP header |
| Secret leakage through a report | Credentials masked by default; a fingerprint allows correlation without the value |

Verified by a test that renders `<script>alert(1)</script>` as a finding title
and asserts it appears escaped.

---

## Deliberate restraint

Some capabilities are withheld because the risk of misuse outweighs the
analytical value:

- **Extracted endpoints are never contacted.** No DNS, no connections, no
  scanning. DroidScope cannot be turned into a scanner by uploading a file,
  and analysing a sample does not notify its operator.
- **No Frida bypass modules.** No SSL unpinning, root-detection bypass or
  biometric bypass ([ADR-008](../ARCHITECTURE_DECISIONS.md)).
- **No automatic certificate installation.** Intercepting TLS requires an
  operator to configure a proxy and install a trust anchor deliberately.
- **No cloud access checks.** A Firebase database's readability is observed as
  a configuration fact, never tested, because testing it without the owner's
  authorisation would be unauthorised access.

## Residual risks

Stated plainly:

1. **A zero-day in a third-party parser** could still achieve code execution in
   the worker. Isolation limits the damage; it does not eliminate the risk.
2. **The artifact store is a sensitive repository** of APKs, decompiled code
   and reports. It is not encrypted at rest by DroidScope; use an encrypted
   volume.
3. **A single API key is a single point of failure** on a shared deployment.
4. **Dynamic analysis genuinely runs untrusted code** on a device. Use a
   disposable device on a segmented network.
5. **Decompiled source trees persist** for `artifact_retention_days`. If the
   analysed application contained secrets, so does that directory.
