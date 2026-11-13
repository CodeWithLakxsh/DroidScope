# Changelog

All notable changes to DroidScope are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Nothing yet.

## [0.1.0] — 2026-11-13

First release. A working static analysis platform with a web interface, a CLI
and evidence-backed reporting.

### Added

**Analysis engine**
- APK validation with hostile-archive defences: zip bomb limits (per entry and
  cumulative), path traversal rejection, symlink refusal, compression method
  allowlist, entry count caps and APK shape verification — all applied before
  any parser reads the file
- Metadata extraction covering package identity, SDK levels, components,
  permissions, signing certificates, multidex and native libraries
- Scan pipeline with six analyzers, per-analyzer timeouts, and execution
  records for analyzers that could not run
- Three profiles: `quick`, `standard` and `full`

**Detection**
- 59 rules across six engines
- 14 structural manifest rules that weigh component kind, target SDK and
  permission protection level before reporting
- 37 declarative pattern rules with required and excluded context
- Secret detection combining provider-specific formats with entropy analysis;
  values are masked and fingerprinted, never stored in plaintext
- Native ELF inspection: architecture, symbols, dependencies, hardening flags
- YARA subsystem with per-file validation and resource limits
- Network indicator extraction classified by routing scope; extracted
  destinations are never contacted
- CWE and OWASP MASVS v2 mappings, validated at rule load time

**Risk and reporting**
- Explainable risk summary: weighted severity × confidence × review status
  through a saturating curve, with a severity floor and coverage caveats.
  Explicitly not a CVSS score
- PDF, HTML, JSON and SARIF 2.1.0 reports rendered from one canonical document
- Every report records the scan id, APK SHA-256, tool versions and the
  analyzers that did not complete

**Platform**
- REST API with 32 endpoints, structured errors, pagination and filtering
- Durable database-backed job queue with atomic claiming, heartbeats and
  stale-lock recovery
- React frontend with 17 pages, light and dark themes
- CLI: `doctor`, `analyze`, `report`, `compare`, `rules`, `server`, `worker`
- APK comparison correlating findings by fingerprint rather than line number
- Dynamic analysis: device discovery and read-only Frida instrumentation,
  disabled by default and requiring explicit per-session authorisation
- Docker Compose deployment with an unprivileged, read-only worker
- Alembic migrations

**Testing**
- 167 backend tests, 31 frontend tests, 7 end-to-end browser tests
- Two fixture Android applications built from source — one deliberately
  insecure, one the corrected counterpart — so every rule can be proven to fire
  on the weakness and stay silent on the correct form

### Known limitations

See [docs/DEVELOPMENT_STATUS.md](docs/DEVELOPMENT_STATUS.md). In summary:
mitmproxy traffic capture is not implemented; dynamic analysis is implemented
but was not verified against live hardware in the development environment;
Redis is accepted as a queue backend but only the database backend exists.

[Unreleased]: https://github.com/CodeWithLakxsh/DroidScope/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/CodeWithLakxsh/DroidScope/releases/tag/v0.1.0
