# Development guide

## Setup

```bash
make setup      # backend venv (uv) + frontend dependencies (npm ci)
make doctor     # check external tooling
make fixtures   # build the test APKs (needs the Android SDK)
```

## Daily commands

```bash
make dev              # API, worker and frontend together
make test             # backend + frontend unit tests
make test-backend     # pytest
make test-frontend    # vitest
make test-e2e         # Playwright against a running stack
make lint             # ruff + eslint
make format           # ruff fix + format
make typecheck        # mypy + tsc
make rules            # validate every rule file
make check            # everything CI runs
```

## Layout

```
backend/app/
  analyzers/     one package per analyzer; base.py defines the contract
  detection/     rule contracts, registry, contexts, the normalised model
  services/      pipeline, scan and APK services, risk, comparison
  reports/       builder + PDF/HTML/JSON/SARIF renderers
  jobs/          durable queue and worker
  api/v1/        routers
  core/          config, logging, errors, capabilities, subprocess, redaction
  storage/       content-addressed artifact store
  models/        SQLAlchemy ORM
  schemas/       Pydantic contracts
```

### Where to make a change

| Task | Place |
|---|---|
| New detection rule | `rules/` (YAML) or `backend/app/detection/rules/` (Python) |
| New analyzer | `backend/app/analyzers/<name>/`, register in `analyzers/registry.py` |
| New endpoint | `backend/app/api/v1/`, include in `main.py` |
| Schema change | `backend/app/models/core.py`, then `make migration m="..."` |
| New page | `frontend/src/pages/`, route in `App.tsx`, nav in `Layout.tsx` |

## Testing

| Layer | Location | What it covers |
|---|---|---|
| Unit | `backend/tests/unit/` | Validation, rules, secrets, risk — no I/O |
| Integration | `backend/tests/integration/` | Full pipeline and API against real fixture APKs |
| Frontend unit | `frontend/tests/` | Helpers, components, API client |
| End to end | `frontend/tests/e2e/` | Browser against a running stack |

Tests that need an external tool **skip with a reason** rather than failing, so
a contributor without JADX can still run the suite. CI installs the tools so
the real path is exercised.

### The rule that matters

A new detection rule needs a test proving it fires on the vulnerable fixture
*and* a test proving it stays silent on the secure fixture. See
[CONTRIBUTING.md](../../CONTRIBUTING.md).

## Fixtures

Two Android applications in `tests/fixtures/`, built from source by
`scripts/development/build_fixture_apk.sh` using aapt2, javac, d8, zipalign and
apksigner. No Gradle, no committed binaries, and the signing key is generated
at build time.

```bash
make fixtures                                    # both
scripts/development/build_fixture_apk.sh secure  # one
```

## Debugging

```bash
droidscope -v analyze app.apk                  # debug logging
DROIDSCOPE_LOG_LEVEL=DEBUG droidscope worker   # verbose worker
```

Run the pipeline directly, without a worker, to get a stack trace in your
debugger:

```python
async with session_scope() as session:
    outcome = await ScanPipeline(session).run(scan_id)
```

Analyzer failures are recorded rather than raised, so check
`analyzer_executions` — or the Analyzer coverage panel on the scan page — when
a scan completes with fewer findings than expected.

## Conventions

- Comments explain *why*. The existing comments that explain Android platform
  behaviour or a security decision are the model to follow.
- Analyzers never raise for an expected condition; they return a status.
- Nothing in a user-reachable code path invents data.
- Severity and status are never conveyed by colour alone in the UI.
- Motion follows [motion.md](motion.md): it orients, explains or acknowledges,
  and every effect is suppressed under `prefers-reduced-motion`.
