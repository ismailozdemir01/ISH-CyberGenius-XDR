# ISH-CyberGenius-XDR

A single defensive XDR investigation workspace built around Microsoft Graph Security and Microsoft Defender for Endpoint APIs.

## Implemented

- Microsoft Graph incident synchronization and incident detail retrieval.
- Incident classification, determination, assignment, status and metadata updates through Graph.
- Incident comments through Graph.
- Microsoft Graph Advanced Hunting with real KQL.
- Investigation history linked to incidents.
- Evidence store for hunting results, correlations and response results.
- Local ingestion for Defender Advanced Hunting-shaped JSON records.
- Connected detections for DeviceProcessEvents and DeviceNetworkEvents.
- Behavioral correlation across process and network telemetry.
- ATT&CK technique mapping for correlated behaviors (`T1059.001`, `T1021.001`).
- Persistent correlation findings and incident-linked attack timeline.
- Microsoft Defender for Endpoint machine inventory.
- Real machine isolation and release-from-isolation response actions.
- Persistent response-action audit trail.
- Markdown incident report generation including correlation findings.
- GitHub Actions CI for Python 3.11–3.13.
- Connected browser dashboard served from the same FastAPI application.
- One FastAPI application; components share the same API and SQLite database.

The application does not generate fake Microsoft responses. Without Microsoft credentials it can still exercise the local telemetry, detection, correlation and persistence path. Microsoft-backed incident, hunting and response endpoints require configured credentials and the corresponding Entra permissions.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
uvicorn app.main:app --reload
```

Configure:

- `TENANT_ID`
- `CLIENT_ID`
- `CLIENT_SECRET`
- `GRAPH_BASE_URL`
- `DEFENDER_API_BASE_URL`

The Graph client uses the `https://graph.microsoft.com/.default` scope. Advanced Hunting requires the appropriate Microsoft Graph Security application permission; Microsoft documents `ThreatHunting.Read.All` as the least-privileged application permission for `runHuntingQuery`.

Incident write operations use Microsoft Graph Security `SecurityIncident.ReadWrite.All`.

Defender for Endpoint response actions use the Defender API token audience `https://api.securitycenter.microsoft.com/.default`. Machine isolation requires the `Machine.Isolate` application permission. These response endpoints perform real actions in the connected Defender tenant; they are not simulations.

## API

### Incidents

- `GET /api/incidents?refresh=true`
- `GET /api/incidents/{incident_id}`
- `PATCH /api/incidents/{incident_id}`
- `POST /api/incidents/{incident_id}/comments`
- `POST /api/incidents/{incident_id}/evidence`
- `GET /api/incidents/{incident_id}/report`

### Hunting, detection and correlation

- `POST /api/hunting` with `{ "query": "DeviceProcessEvents | limit 10", "timespan": "P1D", "incident_id": "..." }`
- `POST /api/telemetry` with Defender-shaped event JSON
- `GET /api/telemetry?table=DeviceProcessEvents`
- `GET /api/detections/rules`
- `POST /api/correlate` to correlate local telemetry and optionally attach findings to an incident
- `GET /api/correlations?incident_id=...`
- `GET /api/timeline/{incident_id}`

The correlation layer currently joins encoded PowerShell and RDP/process activity by device and time window. It is intentionally evidence-driven: a correlation is persisted only from telemetry already present in the local store.

### Defender response

- `GET /api/machines`
- `POST /api/response/isolate`
- `POST /api/response/unisolate`
- `GET /api/response/actions?incident_id=...`

Browser dashboard: `/`

Swagger UI: `/docs`

## Test

```bash
pytest -q
```

The CI workflow runs the test suite on Python 3.11, 3.12 and 3.13.
