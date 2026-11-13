# Dynamic analysis setup

Dynamic analysis installs an application on a device and runs it. It is
**disabled by default** and refuses to start without an explicit per-session
authorisation flag.

> Only analyse applications you own or have written permission to test, on a
> device you are authorised to use.

## What works where

| Capability | Requirement | Notes |
|---|---|---|
| Device discovery | adb | Works everywhere |
| Install and launch | adb, usable device | Works on stock devices |
| Log capture | adb | Works on stock devices |
| Frida instrumentation | frida CLI **and** frida-server on the device | Generally needs root |
| TLS interception | An operator-configured proxy and trust anchor | Not automated |

The honest summary: on a **stock, non-rooted device**, DroidScope can install,
launch and collect logs. Instrumenting a third-party release build needs root,
a debuggable build, or an APK repackaged with frida-gadget. Every session
begins with a capability report stating which of these apply to the selected
device, so you learn this before the session rather than from an empty timeline.

## Emulator setup (recommended)

An emulator is the right target: disposable, isolated and rootable.

```bash
sdkmanager "system-images;android-34;google_apis;arm64-v8a"   # or x86_64
avdmanager create avd -n droidscope-test \
  -k "system-images;android-34;google_apis;arm64-v8a"

$ANDROID_HOME/emulator/emulator -avd droidscope-test -no-snapshot-save &
adb wait-for-device
```

Use a **google_apis** image, not **google_apis_playstore**: the Play image is
not rootable, so `adb root` fails and Frida cannot attach.

### Hardware acceleration

| Platform | Requirement |
|---|---|
| macOS | Hypervisor.framework; no setup needed |
| Linux | KVM — `ls /dev/kvm`, add yourself to the `kvm` group |
| Windows | WHPX or Hyper-V enabled in Windows Features |

Without acceleration the emulator is too slow to be useful.

## frida-server on the device

The server version must match your host `frida` version.

```bash
frida --version                       # note the version
# download frida-server-<version>-android-<arch>.xz from the Frida releases page
unxz frida-server-*.xz
adb root
adb push frida-server /data/local/tmp/
adb shell "chmod 755 /data/local/tmp/frida-server"
adb shell "/data/local/tmp/frida-server &"

frida-ps -U | head                    # confirm it is reachable
```

A mismatched version is the most common failure, and it presents as a confusing
attach error.

## Enabling it in DroidScope

```bash
export DROIDSCOPE_DYNAMIC_ANALYSIS_ENABLED=true
# Only if you intend to use real hardware:
# export DROIDSCOPE_DYNAMIC_ALLOW_PHYSICAL_DEVICES=true
droidscope server & droidscope worker &
```

Open **Dynamic analysis**, pick an application and a device, choose modules,
tick the authorisation box, and start.

## Instrumentation modules

All modules are observational.

| Module | Records |
|---|---|
| `file-access` | File reads and writes, SharedPreferences keys written (keys only, never values) |
| `crypto-api` | Cipher transformations, digest algorithms, key algorithms and lengths — never key material |
| `network-api` | URLs opened through `java.net` and OkHttp |
| `process-ipc` | `Runtime.exec` commands and outgoing Intents |
| `method-trace` | Up to 40 methods of the application's own classes; verbose |

DroidScope ships no module that bypasses certificate validation, root detection
or biometric checks. See [ADR-008](../ARCHITECTURE_DECISIONS.md).

## Why Docker does not include an emulator

Running an Android emulator in a container needs `/dev/kvm` passed through,
which requires a Linux host with KVM and usually a privileged container. That
is neither portable nor a safe default for a tool that handles malware, so
`docker-compose.yml` does not attempt it.

If you want containerised dynamic analysis, run the emulator on a dedicated
Linux host and point a DroidScope worker at it over ADB on a segmented network.
Never expose ADB or Frida beyond that host.

## Isolation checklist

- A dedicated device or emulator, not a daily driver
- A segmented network with no route to production
- No real accounts or credentials on the device
- Reset between samples — an emulator snapshot makes this cheap
- ADB and Frida reachable only from the analysis host
