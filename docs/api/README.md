# API

A versioned REST API under `/api/v1`. The authoritative, always-current
reference is the generated OpenAPI document:

- Interactive: `http://127.0.0.1:8000/docs`
- ReDoc: `http://127.0.0.1:8000/redoc`
- Schema: `http://127.0.0.1:8000/openapi.json`

## Endpoints

### System

| Method | Path | Purpose |
|---|---|---|
| GET | `/health` | Liveness, database state, queue depth |
| GET | `/capabilities` | Installed tooling, analyzer availability, profiles |
| GET | `/analyzers` | Analyzers and the profiles that include them |
| GET | `/rules` | Loaded detection rules with their mappings |

### APKs

| Method | Path | Purpose |
|---|---|---|
| POST | `/apks` | Upload (multipart). Validates before parsing; deduplicates by SHA-256 |
| GET | `/apks` | List, with `search`, `limit`, `offset` |
| GET | `/apks/{apk_id}` | Full metadata |
| GET | `/apks/{apk_id}/icon` | Extracted launcher icon |
| GET | `/apks/{apk_id}/manifest` | Decoded `AndroidManifest.xml` |

### Scans

| Method | Path | Purpose |
|---|---|---|
| POST | `/scans` | Queue a scan |
| GET | `/scans` | List, filterable by `status`, `apk_id`, `profile` |
| GET | `/scans/{scan_id}` | Detail: risk, coverage, limitations, executions |
| POST | `/scans/{scan_id}/cancel` | Request cancellation |
| GET | `/scans/{scan_id}/findings` | Findings, filtered and sorted |
| GET | `/scans/{scan_id}/indicators` | Network indicators |
| GET | `/scans/{scan_id}/artifacts` | Artifacts produced |
| GET | `/scans/{scan_id}/tree` | Browse a source artifact |
| GET | `/scans/{scan_id}/file` | Read one file from an artifact |
| GET | `/scans/{scan_id}/export` | The complete result document as JSON |

### Findings

| Method | Path | Purpose |
|---|---|---|
| GET | `/findings/{finding_id}` | Detail with evidence and review history |
| PATCH | `/findings/{finding_id}/review` | Record a triage decision |

### Reports, comparison, dynamic analysis, settings

| Method | Path | Purpose |
|---|---|---|
| POST | `/reports` | Generate (`pdf`, `html`, `json`, `sarif`) |
| GET | `/reports/{report_id}/download` | Download |
| POST | `/compare` | Compare two APKs |
| GET | `/devices` | Connected devices with capability notes |
| GET | `/dynamic/modules` | Available instrumentation modules |
| POST | `/dynamic/sessions` | Create a session (requires explicit authorisation) |
| GET | `/dynamic/sessions/{id}/events` | Captured runtime events |
| GET/PATCH | `/settings` | Operational settings |

## Conventions

### Errors

Every error has the same shape:

```json
{
  "error": {
    "code": "apk_validation_error",
    "message": "file is not a ZIP archive (an APK must start with a local ZIP header)",
    "details": { "magic": "7468697320" }
  }
}
```

`code` is stable and safe to branch on. Messages never contain server
filesystem paths, and unexpected errors return a generic message while the
detail goes to the server log.

### Pagination

List endpoints take `limit` (1–500, default 50) and `offset`, and return:

```json
{ "items": [], "total": 0, "limit": 50, "offset": 0 }
```

### Authentication

Off by default for local use. When `DROIDSCOPE_REQUIRE_AUTH=true`, mutating
requests need `X-API-Key`. Reads remain open; put the API behind a proxy if
that is not acceptable.

### What the API will not do

- Return a server filesystem path. Artifacts are addressed by scan id and kind.
- Accept a tool path. Executable locations come from the environment only.
- Contact an endpoint extracted from an analysed application.
- Start a dynamic session without `authorised: true` and the server setting enabled.

## Example

```bash
API=http://127.0.0.1:8000/api/v1

APK=$(curl -sX POST $API/apks -F "file=@app.apk" | jq -r .apk.id)
SCAN=$(curl -sX POST $API/scans -H 'Content-Type: application/json' \
        -d "{\"apk_id\":\"$APK\",\"profile\":\"standard\"}" | jq -r .scan.id)

until [ "$(curl -s $API/scans/$SCAN | jq -r .status)" = "completed" ]; do sleep 2; done

curl -s "$API/scans/$SCAN/findings?severity=critical&severity=high" \
  | jq -r '.items[] | "\(.severity)\t\(.rule_id)\t\(.title)"'

REPORT=$(curl -sX POST $API/reports -H 'Content-Type: application/json' \
          -d "{\"scan_id\":\"$SCAN\",\"format\":\"pdf\"}" | jq -r .id)
curl -s -o report.pdf $API/reports/$REPORT/download
```
