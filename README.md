# ISH-CyberGenius-XDR

<p align="center">
  <strong>Defensive XDR Investigation, Correlation & Response Platform</strong>
</p>

<p align="center">
  <a href="https://github.com/ismailozdemir01/ISH-CyberGenius-XDR/actions"><img src="https://img.shields.io/github/actions/workflow/status/ismailozdemir01/ISH-CyberGenius-XDR/ci.yml?branch=main&label=CI" alt="CI"></a>
  <a href="https://github.com/ismailozdemir01/ISH-CyberGenius-XDR"><img src="https://img.shields.io/github/stars/ismailozdemir01/ISH-CyberGenius-XDR?style=flat" alt="GitHub stars"></a>
  <a href="https://github.com/ismailozdemir01/ISH-CyberGenius-XDR/network/members"><img src="https://img.shields.io/github/forks/ismailozdemir01/ISH-CyberGenius-XDR?style=flat" alt="GitHub forks"></a>
  <a href="https://github.com/ismailozdemir01/ISH-CyberGenius-XDR/blob/main/LICENSE"><img src="https://img.shields.io/github/license/ismailozdemir01/ISH-CyberGenius-XDR" alt="License"></a>
  <a href="https://github.com/ismailozdemir01/ISH-CyberGenius-XDR"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB" alt="Python 3.11+"></a>
  <a href="https://github.com/ismailozdemir01/ISH-CyberGenius-XDR"><img src="https://img.shields.io/badge/FastAPI-XDR-009688" alt="FastAPI"></a>
</p>

ISH-CyberGenius-XDR is a defensive, API-driven **Extended Detection and Response (XDR)** workspace for security investigation and response. It combines deterministic detection rules, behavioral correlation, MITRE ATT&CK mapping, explainable risk scoring, incident evidence, entity relationships, timelines, reporting, and real Microsoft security integrations in one Python/FastAPI application.

> **Security-first by design:** the platform is built for defensive security operations. It does not fabricate Microsoft security data. Local detection and correlation operate on evidence actually present in the workspace, while Microsoft-backed operations use the configured Microsoft Graph Security and Microsoft Defender for Endpoint APIs.

---

## Why ISH-CyberGenius-XDR?

Security telemetry is useful only when analysts can turn it into an investigation they can explain and act on.

ISH-CyberGenius-XDR connects the investigation lifecycle:

**Telemetry → Detection → Correlation → ATT&CK → Risk → Evidence → Timeline → Response → Report**

The project is designed to make those relationships explicit and auditable instead of hiding the reasoning behind an opaque black box.

### Core capabilities

- **XDR investigation workspace** for incidents, evidence and investigation history
- **Deterministic detection rules** for suspicious process, scripting and network activity
- **Behavioral correlation** across telemetry using device and time-window relationships
- **MITRE ATT&CK technique mapping** for detections and correlations
- **Explainable risk scoring** with persisted risk factors
- **Entity graph** linking devices, users, processes, IPs, domains, hashes and techniques
- **Attack timelines** built from persisted incident evidence and telemetry
- **Microsoft Graph Security integration** for incidents, comments and Advanced Hunting
- **Microsoft Defender for Endpoint integration** for machine inventory and real isolation/unisolation
- **Persistent response audit trail** for containment actions
- **Markdown incident reports**
- **Browser dashboard** backed by the same API
- **SQLite persistence** for local evidence, telemetry, investigations, correlations and response history
- **API authentication** for every `/api/*` endpoint
- **Security response headers** and GZip middleware
- **Health/readiness probes** for deployment and operations
- **Automated CI** across Python 3.11, 3.12 and 3.13
- **Dependabot security automation** at the repository level

---

## Architecture

```text
                    ┌──────────────────────────────┐
                    │      Browser Dashboard       │
                    └──────────────┬───────────────┘
                                   │
                              Bearer API Key
                                   │
                    ┌──────────────▼───────────────┐
                    │          FastAPI API          │
                    │  Auth • Headers • Operations  │
                    └──────────────┬───────────────┘
                                   │
             ┌─────────────────────┼─────────────────────┐
             │                     │                     │
      ┌──────▼──────┐       ┌──────▼──────┐       ┌──────▼──────┐
      │  Detection  │       │ Correlation │       │   Analytics │
      │    Rules    │       │  + ATT&CK   │       │ Risk / Graph│
      └──────┬──────┘       └──────┬──────┘       └──────┬──────┘
             │                     │                     │
             └─────────────────────┼─────────────────────┘
                                   │
                         ┌─────────▼─────────┐
                         │  SQLite Evidence  │
                         │ Telemetry / Audit │
                         └─────────┬─────────┘
                                   │
                  ┌────────────────┴────────────────┐
                  │                                 │
        ┌─────────▼─────────┐             ┌─────────▼─────────┐
        │ Microsoft Graph   │             │ Microsoft Defender │
        │ Security / Hunting│             │   for Endpoint     │
        └───────────────────┘             └────────────────────┘
```

---

## Detection & correlation

The detection layer currently includes rules covering suspicious PowerShell execution, scripting activity and RDP-related network behavior.

Example rule identifiers:

- `PROC-POWERSHELL-001`
- `PROC-SCRIPT-002`
- `NET-RDP-003`

The correlation engine joins evidence by **device and time window** rather than repeatedly scanning the entire telemetry set. Existing correlation rules include:

- `CORR-PS-ENC-001`
- `CORR-PS-NET-002`
- `CORR-RDP-PROC-003`
- `CORR-PS-RDP-004`

Correlations retain their rule identifiers, risk scores and ATT&CK technique mappings so an analyst can trace why a finding exists.

> The correlation layer does not invent Microsoft events. It operates on telemetry already present in the local evidence store.

---

## Investigation model

An incident can accumulate:

1. **Evidence** — raw or normalized investigation artifacts
2. **Telemetry** — process and network observations
3. **Detections** — deterministic rule matches
4. **Correlations** — multi-event behavioral findings
5. **ATT&CK techniques** — mapped behavioral context
6. **Risk factors** — explainable scoring inputs
7. **Entity relationships** — devices, users, processes, IPs, domains and hashes
8. **Timeline events** — ordered investigation history
9. **Response actions** — audited containment operations
10. **Incident report** — Markdown investigation output

This creates a persistent investigation record rather than a collection of transient API responses.

---

## Microsoft security integrations

### Microsoft Graph Security

The Graph integration supports:

- Incident synchronization and retrieval
- Incident updates
- Incident comments
- Advanced Hunting
- Persisted hunting history

Advanced Hunting uses the Microsoft Graph `runHuntingQuery` operation. The application is designed around application permissions and does not embed Microsoft credentials in source code.

### Microsoft Defender for Endpoint

The Defender integration supports:

- Machine inventory
- Machine isolation
- Machine unisolation
- Persistent response-action auditing

Isolation and unisolation are **real Defender response operations**. They are protected by API authentication and the dashboard requires explicit confirmation before initiating containment.

---

## API

### Operational endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/health` | Liveness probe |
| GET | `/ready` | Readiness probe |
| GET | `/api/overview` | Workspace overview |

### Investigation endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/incidents?refresh=true` | List/synchronize incidents |
| GET | `/api/incidents/{incident_id}` | Incident investigation view |
| PATCH | `/api/incidents/{incident_id}` | Update an incident |
| POST | `/api/incidents/{incident_id}/comments` | Add incident comment |
| POST | `/api/incidents/{incident_id}/evidence` | Add evidence |
| GET | `/api/incidents/{incident_id}/risk` | Risk assessment |
| GET | `/api/incidents/{incident_id}/graph` | Entity graph |
| GET | `/api/incidents/{incident_id}/report` | Markdown report |
| POST | `/api/hunting` | Run Advanced Hunting |
| POST | `/api/telemetry` | Ingest telemetry |
| GET | `/api/telemetry` | Read telemetry |
| GET | `/api/detections/rules` | List detection rules |
| POST | `/api/correlate` | Run behavioral correlation |
| GET | `/api/correlations` | Read correlation findings |
| GET | `/api/timeline/{incident_id}` | Incident timeline |

### Response endpoints

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/machines` | Defender machine inventory |
| POST | `/api/response/isolate` | Isolate a machine |
| POST | `/api/response/unisolate` | Remove machine isolation |
| GET | `/api/response/actions` | Response audit history |

All `/api/*` routes require:

```http
Authorization: Bearer <API_KEY>
```

`/health` and `/ready` remain unauthenticated so deployment infrastructure can perform operational checks.

---

## Quick start

### Requirements

- Python **3.11+**
- Git
- Optional: Microsoft Entra application for Microsoft Graph / Defender integrations

### Install

```bash
git clone https://github.com/ismailozdemir01/ISH-CyberGenius-XDR.git
cd ISH-CyberGenius-XDR

python -m venv .venv
source .venv/bin/activate

pip install -e '.[test]'
cp .env.example .env
```

Windows PowerShell:

```powershell
git clone https://github.com/ismailozdemir01/ISH-CyberGenius-XDR.git
cd ISH-CyberGenius-XDR

python -m venv .venv
.\.venv\Scripts\Activate.ps1

pip install -e '.[test]'
Copy-Item .env.example .env
```

### Configuration

Configure the values in `.env`:

```env
TENANT_ID=
CLIENT_ID=
CLIENT_SECRET=
GRAPH_BASE_URL=https://graph.microsoft.com/v1.0
DEFENDER_API_BASE_URL=https://api.security.microsoft.com
DATABASE_PATH=cybergenuis.db
REQUEST_TIMEOUT=30
API_KEY=
```

Use a long, randomly generated `API_KEY`. Never commit `.env` or real credentials.

### Start

```bash
uvicorn app.main:app --reload
```

Open the dashboard at:

```text
http://127.0.0.1:8000/
```

Swagger UI:

```text
http://127.0.0.1:8000/docs
```

---

## Testing

Run the complete test suite:

```bash
pytest -q
```

Compile-check application and test modules:

```bash
python -m compileall -q app tests
```

CI is configured for:

- Python 3.11
- Python 3.12
- Python 3.13

The workflow installs the project with its test dependencies, compiles the source tree and runs pytest.

---

## Project structure

```text
app/
├── analytics.py       # Risk scoring, graph and timeline analytics
├── config.py          # Environment-backed configuration
├── correlation.py     # Behavioral correlation engine
├── db.py              # SQLite persistence
├── defender.py        # Microsoft Defender API client
├── detection.py       # Deterministic detection rules
├── main.py            # FastAPI application and routes
└── report.py          # Incident report generation

tests/
├── test_analytics.py
├── test_correlation.py
├── test_detection.py
└── test_workflow.py

.github/
└── workflows/
    └── ci.yml

.env.example
SECURITY.md
pyproject.toml
README.md
```

---

## Security model

ISH-CyberGenius-XDR is intended for defensive security operations.

Security controls include:

- Bearer authentication for all application API routes
- Unauthenticated health/readiness probes only
- Security response headers
- No hardcoded Microsoft credentials
- Environment-based secret configuration
- Explicit confirmation for dashboard containment actions
- Persistent response audit trail
- Repository security policy
- Dependabot vulnerability alerts and security updates
- Grouped Dependabot security updates
- Dependency submission
- Python 3.11–3.13 CI coverage

Read **[SECURITY.md](SECURITY.md)** before deploying the application.

For production deployment:

- Use TLS.
- Store credentials in a dedicated secret manager.
- Restrict network access to the API.
- Rotate credentials according to your organization's policy.
- Grant only the Microsoft permissions required by the deployment.
- Treat Defender isolation/unisolation as privileged security operations.

---

## Microsoft permissions

The Microsoft Graph client uses the `https://graph.microsoft.com/.default` scope.

Depending on the enabled functionality, the Entra application requires the corresponding Microsoft Graph / Defender permissions. The project documentation specifically uses:

- `ThreatHunting.Read.All` for Advanced Hunting
- `SecurityIncident.ReadWrite.All` for incident write operations
- Defender for Endpoint `Machine.Isolate` for machine isolation

Review Microsoft's current permission documentation before production deployment because Microsoft permissions and API requirements can change.

---

## Design principles

### Evidence over invention

The system works from persisted telemetry and evidence. Correlation is based on observed records rather than generated events.

### Explainability over opaque scoring

Risk scores are accompanied by factors and investigation context so analysts can understand why an incident received its score.

### Integration over imitation

Microsoft-backed operations use real Microsoft APIs rather than simulated responses.

### Auditability

Investigation data, correlation findings and response actions are persisted so an analyst can reconstruct what happened and what actions were taken.

### Defensive scope

The project is intended for detection, investigation, containment and security operations.

---

## Roadmap

Potential future work includes:

- Additional deterministic detection and correlation rules
- Broader telemetry normalization
- More ATT&CK coverage
- Expanded Microsoft security integrations
- Analyst workflow improvements
- Additional automated security testing
- Broader deployment and observability integrations

---

## Contributing

Contributions that improve detection quality, correlation accuracy, investigation usability, security hardening, documentation or test coverage are welcome.

Before opening a pull request:

```bash
python -m compileall -q app tests
pytest -q
```

Please avoid submitting credentials, tokens, private keys or customer/security telemetry.

---

## License

See [LICENSE](LICENSE) for the repository license.

---

## Security disclosure

Please do not report sensitive vulnerabilities in public issues.

See **[SECURITY.md](SECURITY.md)** for the project's security reporting process.

---

<p align="center">
  <strong>ISH-CyberGenius-XDR</strong><br>
  Defensive XDR • Investigation • Detection • Correlation • Response
</p>
