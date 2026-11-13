# Security Policy

## Reporting a vulnerability in DroidScope

Please report security issues in DroidScope itself privately, through GitHub's
[private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
on this repository. Do not open a public issue for an unfixed vulnerability.

Please include the DroidScope version, your platform, reproduction steps, and
what an attacker gains. If a crafted APK triggers the issue, describe how to
build one rather than attaching a malicious sample.

We aim to acknowledge a report within three working days and to agree a
disclosure timeline with you. Reporters are credited in the changelog unless
they ask otherwise.

### Out of scope

- Findings produced *by* DroidScope about an application you scanned. Those are
  analysis results, not vulnerabilities in DroidScope.
- A false positive or false negative in a detection rule. Please open a normal
  issue with the input that produced it.
- Vulnerabilities in the external tools DroidScope drives (JADX, apktool,
  Ghidra, Frida). Report those upstream; tell us if DroidScope's use of them
  makes the impact worse.
- Running DroidScope in a configuration its documentation warns against, such
  as exposing the API to an untrusted network with authentication disabled.

## Threat model

DroidScope's primary threat is **the input it is asked to analyse**. An APK is
attacker-controlled by definition, and it is handed to several third-party
parsers. The full model is in
[docs/security/threat-model.md](docs/security/threat-model.md); the controls in
summary:

| Threat | Control |
|---|---|
| Zip bomb | Entry count, total uncompressed size and per-entry ratio limits, enforced before extraction |
| Path traversal in archive entries | Entry names validated, and every resolved destination re-checked against the extraction root |
| Symlink extraction attack | Symlink entries rejected outright |
| Malicious filename influencing a path | Files stored under their SHA-256; the uploaded name is display-only |
| Parser exploit via a crafted APK | Analysis runs in a separate worker process with a timeout; the container drops all capabilities and runs read-only |
| Command injection through APK-derived values | Subprocesses are argument vectors; no shell is ever invoked |
| Command execution via configuration | Tool paths come from the environment only, validated as existing executables, and cannot be set through the API |
| Secret leakage through the tool itself | Detected credentials are masked and fingerprinted; plaintext is not stored by default |
| XSS in a generated report | Autoescaped templates, escaped input to the PDF renderer, restrictive CSP, `nosniff` on download |
| Path traversal through the file-browsing API | Storage keys validated, resolved paths re-checked against the artifact root |
| Unintended network contact | Static analysis never contacts an extracted endpoint; proxy variables are stripped from analyzer subprocesses |
| Unintended code execution | An uploaded APK is never executed on the analysis host |

## Deployment guidance

DroidScope defaults suit a single-user local install. For anything shared:

1. **Enable authentication.** Set `DROIDSCOPE_REQUIRE_AUTH=true` and a long
   random `DROIDSCOPE_API_KEY`. Without it, every API caller is trusted.
2. **Do not expose the API directly.** Put it behind a reverse proxy that
   terminates TLS and applies rate limiting.
3. **Keep the database and Redis off the public network.** The supplied
   `docker-compose.yml` does not publish them.
4. **Run workers unprivileged and isolated.** The supplied worker service drops
   all capabilities, uses a read-only root filesystem and sets
   `no-new-privileges`. Keep it that way.
5. **Separate dynamic analysis.** It installs and runs applications. Use a
   dedicated, isolated device or emulator on a segmented network, and never
   expose ADB or Frida to anything but the analysis host.
6. **Set a retention policy.** `DROIDSCOPE_ARTIFACT_RETENTION_DAYS` bounds how
   long decompiled source trees persist. Those trees contain the application's
   full source and any secrets in it.
7. **Treat the artifact store as sensitive.** It holds uploaded APKs,
   decompiled code and reports.

## Handling malicious samples

DroidScope performs static analysis and does not execute an APK on the host.
That said, if you analyse live malware:

- run it on a machine you are prepared to rebuild;
- keep the artifact store on an encrypted volume;
- do not enable dynamic analysis against a device on a production network;
- remember that extracted indicators are **not** contacted by DroidScope, so
  nothing in the tool will alert an operator that their sample was analysed.

## Supported versions

DroidScope is pre-1.0. Security fixes are applied to `main` and released in the
next version. There is no long-term support branch yet.
