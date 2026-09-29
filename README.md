# ISH-CyberGenius-XDR

A defensive XDR investigation and response workspace built around Microsoft Graph Security and Microsoft Defender for Endpoint APIs. The core analytics are deterministic detection rules, behavioral correlation, ATT&CK mapping and explainable risk scoring; Microsoft APIs provide the external investigation and response integrations.

## Final stack

- Microsoft Graph incident synchronization, retrieval, updates and comments.
- Real Microsoft Graph Advanced Hunting with persisted investigation history.
- Evidence store spanning hunting, behavioral correlation and response actions.
- Defender-shaped telemetry ingestion and connected local detection rules.
- Behavioral correlation across process/network activity with ATT&CK technique mapping.
- Incident risk scoring with explainable factors.
- Entity graph for devices, users, processes, IPs, domains, hashes and ATT&CK techniques.
- Persistent attack timeline and incident-linked correlation findings.
- Defender for Endpoint machine inventory and real isolate/unisolate response actions.
- Persistent response audit trail.
- Markdown incident reports.
- Browser dashboard using the same live API.
- GZip compression and baseline security response headers.
- `/health` and `/ready` operational probes.
- Workspace telemetry/correlation overview endpoint.
- GitHub Actions CI for Python 3.11–3.13.

The application does not fabricate Microsoft responses. All `/api/*` endpoints require `Authorization: Bearer <API_KEY>`; `/health` and `/ready` remain unauthenticated operational probes. Without Microsoft credentials, the local telemetry, detection, correlation, analytics and persistence paths remain usable. Microsoft-backed incident, hunting and response operations require the appropriate Entra application permissions and configured credentials.

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
- `DATABASE_PATH`
- `REQUEST_TIMEOUT`
- `API_KEY` — required to access `/api/*`; use a long random value

## Operations

- Browser dashboard: `/`
- Swagger UI: `/docs`
- Liveness: `GET /health`
- Readiness: `GET /ready`
- Workspace overview: `GET /api/overview`

## Investigation API

- `GET /api/incidents?refresh=true`
- `GET /api/incidents/{incident_id}` — incident, risk, evidence, investigations, correlations and response history
- `PATCH /api/incidents/{incident_id}`
- `POST /api/incidents/{incident_id}/comments`
- `POST /api/incidents/{incident_id}/evidence`
- `GET /api/incidents/{incident_id}/risk`
- `GET /api/incidents/{incident_id}/graph`
- `GET /api/incidents/{incident_id}/report`
- `POST /api/hunting`
- `POST /api/telemetry`
- `GET /api/telemetry`
- `GET /api/detections/rules`
- `POST /api/correlate`
- `GET /api/correlations`
- `GET /api/timeline/{incident_id}`

The correlation layer is evidence-driven. It joins telemetry already present in the local store by device and time window; it does not invent Microsoft events.

## Defender response

- `GET /api/machines`
- `POST /api/response/isolate`
- `POST /api/response/unisolate`
- `GET /api/response/actions`

Isolation and unisolation call Microsoft Defender for Endpoint directly. The dashboard requires an explicit confirmation before these real containment operations. API authentication is enforced before the request can reach the Defender client.

The Graph client uses the `https://graph.microsoft.com/.default` scope. Advanced Hunting requires the appropriate Microsoft Graph Security application permission; Microsoft documents `ThreatHunting.Read.All` as the least-privileged application permission for `runHuntingQuery`.

Incident write operations use Microsoft Graph Security `SecurityIncident.ReadWrite.All`.

Defender for Endpoint response actions use the documented Defender API token audience `https://api.securitycenter.microsoft.com/.default`. Machine isolation requires the `Machine.Isolate` application permission.

## Test

```bash
pytest -q
```

The CI workflow runs the test suite on Python 3.11, 3.12 and 3.13. If GitHub Actions reports a job-start failure with no executable steps, treat that as CI infrastructure/workflow-run failure rather than as a pytest failure; run `pytest -q` locally to validate the suite.

## Security

See `SECURITY.md` before deploying or changing repository visibility. Before making the repository public, review Git history and enable GitHub secret scanning/push protection and code scanning.
