# Troubleshooting

## `droidscope doctor` reports a tool as missing that I installed

DroidScope searches `PATH` at startup. If the tool is installed somewhere else,
point at it explicitly:

```bash
export DROIDSCOPE_JADX_PATH=/opt/jadx/bin/jadx
```

The path is validated as an existing executable file at startup — a wrong path
fails loudly rather than silently disabling the analyzer.

## The source analyzer reports "unavailable" but JADX is installed

JADX is a JVM application. `java` must also be on `PATH`. Check `droidscope
doctor`: if `java` shows as missing, the source analyzer cannot run regardless
of JADX.

On macOS with Homebrew, `openjdk` is keg-only and not linked by default:

```bash
sudo ln -sfn /opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk \
             /Library/Java/JavaVirtualMachines/openjdk-17.jdk
```

## A scan stays "queued" forever

No worker is running. Start one:

```bash
droidscope worker
```

Both processes must share the same `DROIDSCOPE_DATA_DIR` (or database URL). A
worker pointed at a different data directory polls an empty queue — a common
mistake when one process is started with an `.env` file and the other without.

## A scan fails with "the stored APK file is missing from artifact storage"

The database and artifact store have diverged, usually because `DATA_DIR`
changed or the artifact directory was cleared while rows remained. Re-upload
the APK, or point `DROIDSCOPE_DATA_DIR` back at the original directory.

## The upload is rejected and I believe the APK is valid

The error names the specific check. Common causes:

| Message | Cause |
|---|---|
| `not a ZIP archive` | The file is not an APK, or the download was truncated |
| `does not contain AndroidManifest.xml` | A plain ZIP, or an `.aab` bundle rather than an APK |
| `does not carry a DEX magic header` | Corrupt, or deliberately crafted |
| `exceeds the maximum permitted compression ratio` | Possible zip bomb; raise `DROIDSCOPE_MAX_COMPRESSION_RATIO` only if you trust the file |
| `symbolic link entry` | Refused unconditionally; symlinks in an APK are not legitimate |

DroidScope analyses APKs, not Android App Bundles. Convert an `.aab` with
`bundletool build-apks` first.

## Decompilation times out on a large APK

Raise the budget:

```bash
export DROIDSCOPE_DECOMPILE_TIMEOUT_SECONDS=2400
export DROIDSCOPE_ANALYZER_TIMEOUT_SECONDS=3000
```

A timed-out analyzer is recorded with that status — the scan completes and says
what is missing rather than failing entirely.

## The worker is killed on a large APK

Decompilation is memory heavy. Lower `DROIDSCOPE_ANALYSIS_CONCURRENCY` to 1, or
raise the container memory limit. In `docker-compose.yml` the worker is capped
at 4 GB.

## Secrets appear masked and I need the value

By design. Masking is controlled by `DROIDSCOPE_REDACT_SECRETS_IN_REPORTS`.
Rather than disabling it, use the evidence location — file and line — to read
the value from the decompiled source in the code explorer. That keeps the
credential out of the database and out of every report.

## The frontend shows "API offline"

1. Is the API running? `curl http://127.0.0.1:8000/api/v1/health`
2. Is the dev server proxying to the right place? The proxy target is
   `DROIDSCOPE_API_URL`, default `http://127.0.0.1:8000`.
3. In production, is CORS configured? `DROIDSCOPE_CORS_ORIGINS` must include
   the origin serving the frontend.

## Vite starts on a port other than 5173

Another process holds 5173; Vite picks the next free port and prints it. This
is harmless — use the printed URL. Set `strictPort: true` in
`vite.config.ts` if you would rather it fail.

## No devices appear under dynamic analysis

In order:

1. `adb devices` — if empty, the problem is below DroidScope.
2. `unauthorized` means the device has not accepted this host's key; accept the
   prompt on the device.
3. Physical devices are hidden unless
   `DROIDSCOPE_DYNAMIC_ALLOW_PHYSICAL_DEVICES=true`.
4. Dynamic analysis itself is off unless
   `DROIDSCOPE_DYNAMIC_ANALYSIS_ENABLED=true`.

## A dynamic session produces only log events

The session's capability report explains why: instrumentation needs the Frida
CLI on the host *and* a running `frida-server` on the device, which generally
needs root. On a non-rooted device, instrument a debuggable build or repackage
with frida-gadget. DroidScope reports this rather than producing an empty
timeline and calling it success.

## A rule fires on code I believe is correct

That is a bug worth reporting — include the snippet. Meanwhile, mark the
finding a false positive, which removes it from the risk score and records the
decision.

## `droidscope rules validate` reports zero rules

The rule directory could not be found. From a checkout it is discovered
automatically; a packaged or containerised install has no repository layout
beside it, so point at the rules explicitly:

```bash
export DROIDSCOPE_RULES_DIR=/path/to/rules
```

The command exits non-zero when no rules load, so a deployment that cannot find
them fails loudly rather than appearing healthy while detecting nothing.

## Tests skip with "the fixture APK has not been built"

Build them:

```bash
make fixtures
```

This needs the Android SDK (build-tools and a platform `android.jar`). Set
`ANDROID_SDK_ROOT` if it is not in the default location.
