# ISH-CyberGenius-XDR

A single defensive XDR investigation workspace built around the Microsoft Graph Security API and the Microsoft 365 Defender advanced-hunting model.

## Implemented

- Microsoft Graph `GET /security/incidents` synchronization into SQLite.
- Microsoft Graph `POST /security/runHuntingQuery` for real KQL hunting.
- Local ingestion for Defender Advanced Hunting-shaped JSON records.
- Connected detections for `DeviceProcessEvents` and `DeviceNetworkEvents`.
- Persistent investigation history.
- One FastAPI application; components share the same API and database.

The application does not generate fake Microsoft responses. Without Graph credentials it runs the local ingestion/detection path; with credentials it talks to Microsoft Graph directly.

## Run

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
uvicorn app.main:app --reload
```

Configure `TENANT_ID`, `CLIENT_ID`, and `CLIENT_SECRET` for Microsoft Graph application authentication. The app requests `https://graph.microsoft.com/.default`; the Entra application must have the required Graph Security application permission and admin consent.

For Advanced Hunting, Microsoft documents `ThreatHunting.Read.All` as the least-privileged application permission for `runHuntingQuery`. The Microsoft Graph Security API replaces the older Defender Advanced Hunting endpoints.

## API

- `GET /health`
- `GET /api/incidents?refresh=true`
- `POST /api/hunting` with `{ "query": "DeviceProcessEvents | limit 10", "timespan": "P1D" }`
- `POST /api/telemetry` with Defender-shaped event JSON
- `GET /api/telemetry?table=DeviceProcessEvents`
- `GET /api/detections/rules`

Swagger UI: `/docs`

## Test

```bash
pytest -q
```
