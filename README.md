# OZHEX-CyberGenius-XDR

<p align="center"><strong>Defensive XDR Investigation, Correlation & Response Platform</strong></p>

OZHEX-CyberGenius-XDR is a defensive, API-driven **Extended Detection and Response (XDR)** workspace for security investigation and response. It combines deterministic detection, behavioral correlation, MITRE ATT&CK mapping, explainable risk scoring, evidence, entity relationships, timelines, reporting and Microsoft security integrations in one Python/FastAPI application.

> **Security-first:** the platform does not fabricate Microsoft security data. Local detection/correlation operates on evidence present in the workspace; Microsoft-backed operations use configured Microsoft Graph Security, Microsoft Defender for Endpoint and Microsoft Translator APIs.

## Core capabilities

- XDR investigation workspace for incidents, evidence and investigation history
- Deterministic detection rules for suspicious process, scripting and network activity
- Behavioral correlation across telemetry using device and time-window relationships
- MITRE ATT&CK technique mapping and explainable risk scoring
- Entity graph and attack timelines
- Microsoft Graph Security incidents, comments and Advanced Hunting
- Microsoft Defender for Endpoint inventory, isolation and unisolation
- Persistent response audit trail and Markdown incident reports
- SQLite persistence and authenticated API routes
- Security headers, health/readiness probes and GZip middleware
- Browser speech-to-text analyst input
- Automatic language detection and translation through Microsoft Translator
- CI validation on Python 3.11, 3.12 and 3.13
- Dependabot security automation

## Investigation lifecycle

**Telemetry → Detection → Correlation → ATT&CK → Risk → Evidence → Timeline → Response → Report**

## Microsoft integrations

### Microsoft Graph Security

- Incident synchronization and retrieval
- Incident updates and comments
- Advanced Hunting through `runHuntingQuery`
- Persisted hunting history

### Microsoft Defender for Endpoint

- Machine inventory
- Machine isolation
- Machine unisolation
- Response-action auditing

Isolation/unisolation are real Defender response operations and require explicit dashboard confirmation.

### Microsoft Translator

`POST /api/translate` detects the source language and translates analyst text to a selected target language. Browser speech recognition is performed by the Web Speech API; only the resulting text is sent to the backend when translation is requested.

## API

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Liveness |
| GET | `/ready` | Readiness |
| GET | `/api/overview` | Workspace overview |
| GET | `/api/incidents?refresh=true` | List/synchronize incidents |
| GET | `/api/incidents/{incident_id}` | Investigation view |
| PATCH | `/api/incidents/{incident_id}` | Update incident |
| POST | `/api/incidents/{incident_id}/comments` | Add comment |
| POST | `/api/incidents/{incident_id}/evidence` | Add evidence |
| GET | `/api/incidents/{incident_id}/risk` | Risk assessment |
| GET | `/api/incidents/{incident_id}/graph` | Entity graph |
| GET | `/api/incidents/{incident_id}/report` | Markdown report |
| POST | `/api/hunting` | Advanced Hunting |
| POST | `/api/translate` | Language detection + translation |
| POST | `/api/telemetry` | Ingest telemetry |
| GET | `/api/telemetry` | Read telemetry |
| GET | `/api/detections/rules` | Detection rules |
| POST | `/api/correlate` | Behavioral correlation |
| GET | `/api/correlations` | Correlation findings |
| GET | `/api/timeline/{incident_id}` | Incident timeline |
| GET | `/api/machines` | Defender inventory |
| POST | `/api/response/isolate` | Isolate machine |
| POST | `/api/response/unisolate` | Remove isolation |
| GET | `/api/response/actions` | Response audit history |

All `/api/*` routes require `Authorization: Bearer <API_KEY>`.

## Quick start

```bash
git clone https://github.com/ismailozdemir01/OZHEX-CyberGenius-XDR.git
cd OZHEX-CyberGenius-XDR
python -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
cp .env.example .env
uvicorn app.main:app --reload
```

Windows PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[test]"
Copy-Item .env.example .env
python main.py
```

Dashboard: `http://127.0.0.1:8000/`  
Swagger: `http://127.0.0.1:8000/docs`

## Configuration

```env
TENANT_ID=
CLIENT_ID=
CLIENT_SECRET=
API_KEY=
DATABASE_PATH=./data/xdr.db
GRAPH_BASE_URL=https://graph.microsoft.com/v1.0
DEFENDER_API_BASE_URL=https://api.security.microsoft.com
TRANSLATOR_ENDPOINT=https://api.cognitive.microsofttranslator.com
TRANSLATOR_KEY=
TRANSLATOR_REGION=
REQUEST_TIMEOUT=30
```

Never commit `.env` or real credentials.

## Testing

```bash
python -m compileall -q app tests
pytest -q
```

CI validates Python 3.11, 3.12 and 3.13.

## Project structure

```text
app/
├── analytics.py
├── config.py
├── correlation.py
├── db.py
├── defender.py
├── detection.py
├── main.py
├── report.py
└── translator.py

tests/
├── test_analytics.py
├── test_correlation.py
├── test_detection.py
├── test_translator.py
└── test_workflow.py

.github/workflows/ci.yml
.env.example
SECURITY.md
pyproject.toml
README.md
```

## Security model

- Bearer authentication for application API routes
- Unauthenticated health/readiness probes only
- Security response headers
- No hardcoded Microsoft credentials
- Environment-based secret configuration
- Explicit confirmation for containment actions
- Persistent response audit trail
- Dependabot security automation
- Python 3.11–3.13 CI coverage

For production use, deploy behind TLS/reverse proxy, use dedicated secret management, restrict network access, rotate credentials and grant only required Microsoft permissions.

## Release status

**Version 1.2.0 — OZHEX branding release.**

The software baseline includes XDR investigation, detection, correlation, Microsoft Graph/Defender integration, response auditing, speech-to-text, automatic language detection and Microsoft Translator integration. The CI gate must remain green before release tagging.

Live Microsoft tenant validation remains environment-dependent and requires valid Graph, Defender and Translator credentials.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Run compile checks and the full pytest suite before submitting changes.

## License

**Proprietary / All Rights Reserved.** The public GitHub repository is source-visible for evaluation and security review; it is not open-source software. Commercial use, redistribution, resale, and production deployment require a separate OZHEX commercial license. Commercial licenses are sold through the official OZHEX product offering, including Gumroad.

See [LICENSE](LICENSE) for the full terms.
