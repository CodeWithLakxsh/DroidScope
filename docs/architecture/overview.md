# Architecture overview

DroidScope is three processes over one database and one artifact store.

```mermaid
flowchart TB
    subgraph browser[Browser]
        UI["React SPA<br/>17 pages"]
    end

    subgraph apiproc["API process (droidscope server)"]
        ROUTES["FastAPI routers<br/>32 endpoints"]
        INGEST["Ingestion<br/>stream, hash, validate"]
        QUERY["Query services"]
        REPORTS["Report engine"]
    end

    subgraph workerproc["Worker process (droidscope worker)"]
        CLAIM["Job claim loop"]
        PIPELINE["Scan pipeline"]
        ANALYZERS["Analyzers"]
        NORMALISE["Finding normalisation"]
        RISK["Risk summary"]
    end

    subgraph external["External tools (subprocesses)"]
        JADX[JADX]
        APKTOOL[apktool]
        GHIDRA[Ghidra headless]
        ADB[adb / Frida]
    end

    subgraph persistence[Persistence]
        DB[("PostgreSQL or SQLite<br/>19 tables")]
        STORE[["Artifact store<br/>content addressed"]]
    end

    UI -->|"JSON over HTTP"| ROUTES
    ROUTES --> INGEST --> STORE
    ROUTES --> QUERY --> DB
    ROUTES -->|"enqueue job"| DB
    REPORTS --> DB
    REPORTS --> STORE

    CLAIM -->|"atomic UPDATE"| DB
    CLAIM --> PIPELINE --> ANALYZERS
    ANALYZERS -->|"argv, no shell"| external
    ANALYZERS --> STORE
    ANALYZERS --> NORMALISE --> DB
    NORMALISE --> RISK --> DB
```

## Why the work is split

Decompiling an APK is CPU and memory heavy and can take minutes. Running it
inside an HTTP handler would tie up a request worker, make timeouts
meaningless, and let one large APK degrade the whole service. The API therefore
does only cheap, bounded work — validate, hash, store, enqueue — and a separate
worker process does the analysis.

This also contains the blast radius. The worker is the process that hands
untrusted input to third-party parsers, so it is the one that runs with a
read-only root filesystem, no Linux capabilities and a memory limit.

## Request to finding

```mermaid
sequenceDiagram
    autonumber
    participant U as Browser
    participant A as API
    participant S as Artifact store
    participant D as Database
    participant W as Worker
    participant T as External tools

    U->>A: POST /apks (multipart)
    A->>A: stream to temp, hash, enforce size cap
    A->>A: validate archive (bomb, traversal, symlink, shape)
    A->>A: extract metadata (androguard)
    A->>S: store at apks/<aa>/<sha256>.apk
    A->>D: insert apk_artifacts
    A-->>U: 201 with metadata

    U->>A: POST /scans {apk_id, profile}
    A->>D: insert scans + jobs row
    A-->>U: 201 scan queued

    loop until claimed
        W->>D: UPDATE jobs SET status='running' WHERE status='queued'
    end

    W->>D: load scan, APK, rule overrides
    W->>W: discover tool capabilities
    loop each analyzer in profile
        W->>T: run tool (timeout, own process group)
        T-->>W: output or failure
        W->>S: store artifacts
        W->>D: insert analyzer_executions (including failures)
    end
    W->>W: normalise findings, mask secrets
    W->>D: insert findings + evidence
    W->>W: calculate risk with coverage
    W->>D: update scan, complete job

    U->>A: GET /scans/{id}
    A->>D: read
    A-->>U: findings, risk, coverage, limitations
```

Steps 3 and 4 are ordered deliberately: nothing parses the archive until it has
passed the structural checks.

## Components

### API process

FastAPI with versioned routes under `/api/v1`. Domain errors map to structured
responses with a stable `code`, and the catch-all handler never leaks a stack
trace or a filesystem path. Security headers are applied by middleware.

### Worker process

Claims jobs with a conditional `UPDATE`, so two workers racing for the same job
cannot both win. Each running job heartbeats; a job whose worker died is
returned to the queue after the stale-lock timeout. Concurrency is bounded by
`analysis_concurrency`.

### Analyzers

Every analyzer implements the same interface: declare required capabilities,
check prerequisites, analyse, return a result. Failures become statuses, never
exceptions that abort the scan. Analyzers publish data for later analyzers
through a shared dictionary — the source analyzer decompiles once and the
secret and Firebase rules reuse that tree.

### Rule engines

| Engine | Kind | Context consumed |
|---|---|---|
| `manifest-analyzer` | Structural Python | Parsed manifest model and network security config |
| `source-analyzer` | Declarative YAML | Decompiled source tree |
| `secret-analyzer` | Structural Python | Decompiled source tree |
| `firebase-analyzer` | Structural Python | Decoded resources |
| `native-analyzer` | Structural Python | ELF inspection results |
| `network-indicator-analyzer` | Structural Python | Extracted indicators |

### Persistence

Relational data in PostgreSQL or SQLite; large artifacts on disk. A decompiled
source tree can be hundreds of megabytes, which does not belong in a table, so
the database holds a storage key and the artifact store resolves it.

## Further reading

- [Analysis pipeline](pipeline.md)
- [Data model](data-model.md)
- [Job lifecycle](job-lifecycle.md)
- [Risk scoring](risk-scoring.md)
- [Threat model](../security/threat-model.md)
