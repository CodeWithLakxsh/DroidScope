# Development status

Last updated: 2026-11-13. This file records what is implemented, what is
partially implemented, what is not, and — importantly — which claims are backed
by a test that actually ran on this machine versus which remain unverified.

Verification environment: macOS 26.6.2, Apple M2, 8 GB RAM, Python 3.12.13,
Node 22.23.3, JDK 17.0.19, JADX 1.5.6, apktool 3.0.3, Ghidra 12.2, Frida 17.6.2,
yara-python 4.5.4, Android SDK (build-tools 37.0.0, platform android-37).

---

## Summary

| Area | State | Verified how |
|---|---|---|
| APK validation and ingestion | Complete | 26 unit tests, including zip bomb, traversal, symlink and compression attacks |
| Metadata extraction | Complete | Integration tests against two APKs built from source |
| Manifest analysis (14 rules) | Complete | 31 unit tests plus fixture integration tests |
| Source analysis (37 pattern rules) | Complete | Fixture integration tests through real JADX decompilation |
| Secret detection | Complete | 20 unit tests covering formats, entropy, masking and false positives |
| Native ELF inspection | Complete | Verified against real Android NDK libraries |
| YARA subsystem | Complete | 8 starter rules compile and match; verified in-process |
| Network indicators | Complete | Unit tests for scope classification; runs in every scan |
| Risk scoring | Complete | 11 unit tests covering weighting, saturation, severity floor and coverage |
| Scan pipeline and worker | Complete | End-to-end through the API with a real background worker |
| REST API (32 endpoints) | Complete | 21 API tests |
| Reports (PDF/HTML/JSON/SARIF) | Complete | Generated and parsed back; PDF verified with pypdf |
| Frontend (17 pages) | Complete | 31 unit tests, 7 Playwright E2E tests, builds clean |
| APK comparison | Complete | Service implemented and wired; see gaps below |
| CLI | Complete | All commands exercised manually |
| Docker deployment | Config validated | `docker compose config` passes; **images not built** (see gaps) |
| Dynamic analysis | Implemented, **partially unverified** | See the section below |

Test totals on this machine: **167 backend tests**, **31 frontend tests**,
**7 end-to-end tests**, all passing. Ruff clean, TypeScript clean.

---

## Verified end to end

The full acceptance path has been executed against a running stack with a real
background worker and a real browser:

1. start the API and worker, open the dashboard
2. upload `vulnerable-app.apk` (20,964 bytes, built from source)
3. archive validated; SHA-256 computed; metadata extracted
4. scan queued, claimed by the worker, completed in ~2.5 s
5. **52 findings** persisted — 5 critical, 16 high, 18 medium, 9 low, 4 info
6. findings displayed with evidence; a finding marked false positive
7. PDF generated (29 pages), downloaded, verified to start with `%PDF-`
8. API and worker restarted; results still present and identical

The discriminating test: the **secure fixture**, built from the same APIs used
correctly, produces **3 findings** — one informational launcher activity, one
low-severity exported App Link handler, one informational note that certificate
pinning is not configured. No critical, high or medium findings.

---

## Partially implemented

### Dynamic analysis

**Implemented and verified:**

- device discovery over ADB, including state, properties, root and
  frida-server checks — verified against a host with no device attached, where
  it correctly reports why no devices are listed
- the capability report that states, per device, what will and will not work
- session lifecycle, event persistence, artifact export, API and UI

**Implemented but not verified against live hardware:** installing, launching
and instrumenting an application. The verification machine has 8 GB of RAM and
was running the backend, worker, frontend and a browser; starting an Android
emulator alongside them would have caused heavy swapping, so no session was run
against a live device.

What this means concretely: the ADB and Frida adapters are written and
type-checked, their failure paths are exercised, but **no runtime event has
been captured from a real device in this environment**. Treat the dynamic
subsystem as untested until you have run it yourself. It is disabled by default
and refuses to start without an explicit per-session authorisation flag.

To verify it yourself:

```bash
$ANDROID_HOME/emulator/emulator -avd <your_avd> -no-snapshot &
adb wait-for-device
export DROIDSCOPE_DYNAMIC_ANALYSIS_ENABLED=true
droidscope server & droidscope worker &
# then create a session from the Dynamic analysis page
```

### Network capture (mitmproxy)

The capability is detected and reported, and the UI states that TLS payloads
are not decrypted. **There is no mitmproxy capture implementation yet** — no
traffic is recorded. The honest position in the product is that
`network_capture: false` appears in every session capability report.

### Ghidra integration

The adapter is complete: it drives `analyzeHeadless`, writes a structured
summary through a Jython export script, enforces a timeout and discards the
scratch project. Ghidra 12.2 was **detected** on the verification machine and
the adapter correctly reports its availability. A **full headless run was not
executed** — on an 8 GB machine it competes with the rest of the stack for
memory. When Ghidra is absent, the native analyzer states plainly that the ELF
inspection came from DroidScope's own parser.

### Docker images

`docker compose config` validates and the Dockerfiles are complete, but the
**images were not built** on the verification machine: the Docker daemon was
not running, and the build downloads a JRE, JADX and apktool over a ~90 KB/s
link. The `docker.yml` workflow builds both images on every relevant push, so
CI covers this.

---

## Not implemented

| Item | Note |
|---|---|
| mitmproxy traffic capture | Capability detection only; see above |
| Redis-backed queue | `queue_backend` accepts `redis`, but only the database backend is implemented. The database backend is correct and durable; Redis would only add a wake-up signal |
| Rule enable/disable through the API | The model (`detection_rule_states`) and the pipeline honour it; no endpoint writes to it yet |
| Multi-user accounts and per-user isolation | A single shared API key is the only authentication. Deployments with more than one user need a reverse proxy to separate them |
| Incremental or cached decompilation | Each standard scan decompiles from scratch. Scan reuse avoids repeating identical work, but a changed profile re-decompiles |
| Dynamic analysis finding generation | Runtime events are captured and displayed but do not yet produce findings through the rule engine |

---

## Known issues

1. **`findings_by_category` on the dashboard counts across all scans**, not per
   application. Intentional for now, but the label could mislead.
2. **The code explorer lists at most 600 files at a time**, filtered client
   side. A large application needs the filter box. Virtualised scrolling would
   be better.
3. **Scan progress is polled, not pushed.** The API exposes progress on the
   scan resource and the UI polls every 1.5 s while a scan is active. Server-
   sent events would be smoother.
4. **`mypy` is advisory in CI.** The codebase is extensively annotated but not
   yet strict-clean, mostly around third-party parser types.

---

## Environment limitations encountered during development

Recorded because they shaped what could be verified:

- **8 GB RAM.** Prevented running an Android emulator and a full Ghidra
  headless analysis alongside the rest of the stack.
- **~90 KB/s network.** A dependency install stalled on a hung connection and
  needed restarting; this is why the backend install is split and why CI pins
  tool versions explicitly.
- **Port 5173 in use** by an unrelated project on the verification machine, so
  the dev server ran on 5175. The Vite config does not use `strictPort`, which
  is why this was a non-event.
- **Docker daemon not running**, so images were not built locally.

---

## Next engineering tasks, in priority order

1. **Verify dynamic analysis against a live emulator** and record the result
   here. This is the largest gap between what the code does and what has been
   proven.
2. **Implement mitmproxy capture**, or remove the capability from the UI. The
   current state is honest but incomplete.
3. **Turn runtime events into findings** so dynamic analysis contributes to the
   risk summary.
4. **Add an endpoint for rule enable/disable**, since the data model and
   pipeline already support it.
5. **Virtualise the code explorer tree** so large applications browse smoothly.
6. **Push scan progress over SSE** instead of polling.
7. **Make `mypy` blocking** once the remaining annotation gaps are closed.
8. **Expand the rule set**, particularly around Kotlin coroutine and Compose
   patterns, which the current source rules do not cover well.
