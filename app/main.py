from typing import Any, Literal
from fastapi import FastAPI, HTTPException
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel, ConfigDict, Field
from .config import settings
from .db import Database
from .defender import DefenderClient
from .detection import detect, RULES
from .report import build_incident_report

app=FastAPI(title=settings.app_name, version="0.2.0")
db=Database(settings.database_path)

def defender() -> DefenderClient:
    if not settings.graph_configured:
        raise HTTPException(
            503,
            "Microsoft credentials are not configured. Set TENANT_ID, CLIENT_ID and CLIENT_SECRET.",
        )
    return DefenderClient(
        settings.tenant_id,
        settings.client_id,
        settings.client_secret,
        settings.graph_base_url,
        settings.request_timeout,
        settings.defender_api_base_url,
    )

class HuntingRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=20000)
    timespan: str | None = Field(default=None, max_length=100)
    incident_id: str | None = Field(default=None, max_length=200)

class IngestRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    table: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{1,127}$")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=10000)

class IncidentUpdateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    assigned_to: str | None = Field(default=None, max_length=320)
    classification: str | None = Field(default=None, max_length=80)
    determination: str | None = Field(default=None, max_length=80)
    custom_tags: list[str] | None = Field(default=None, max_length=50)
    description: str | None = Field(default=None, max_length=10000)
    display_name: str | None = Field(default=None, max_length=500)
    severity: Literal["unknown","informational","low","medium","high","unknownFutureValue"] | None = None
    status: Literal["active","resolved","redirected"] | None = None
    resolving_comment: str | None = Field(default=None, max_length=5000)
    summary: str | None = Field(default=None, max_length=10000)

class IncidentCommentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    comment: str = Field(min_length=1, max_length=10000)

class EvidenceRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source_type: str = Field(min_length=1, max_length=100)
    source_id: str | None = Field(default=None, max_length=500)
    title: str = Field(min_length=1, max_length=500)
    data: dict[str, Any]

class MachineActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    incident_id: str | None = Field(default=None, max_length=200)
    machine_id: str = Field(min_length=1, max_length=200)
    comment: str = Field(min_length=1, max_length=2000)

class IsolateRequest(MachineActionRequest):
    isolation_type: Literal["Full","Selective","UnManagedDevice"] = "Full"

@app.get("/health")
def health():
    return {
        "status":"ok",
        "graph_configured":settings.graph_configured,
        "database":settings.database_path,
        "version":app.version,
    }

@app.get("/api/incidents")
async def list_incidents(limit: int = 100, refresh: bool = True):
    limit=min(max(limit,1),100)
    if refresh and settings.graph_configured:
        data=await defender().incidents(limit)
        db.upsert_incidents(data.get("value",[]))
    return {"value":db.list_incidents(limit)}

@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id: str, refresh: bool = True):
    if refresh and settings.graph_configured:
        data=await defender().incident(incident_id)
        db.upsert_incidents([data])
    incident=db.incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return {
        "incident":incident,
        "investigations":db.investigations(incident_id),
        "evidence":db.evidence(incident_id),
        "response_actions":db.response_actions(incident_id),
    }

@app.patch("/api/incidents/{incident_id}")
async def update_incident(incident_id: str, req: IncidentUpdateRequest):
    changes={}
    mapping={
        "assigned_to":"assignedTo",
        "classification":"classification",
        "determination":"determination",
        "custom_tags":"customTags",
        "description":"description",
        "display_name":"displayName",
        "severity":"severity",
        "status":"status",
        "resolving_comment":"resolvingComment",
        "summary":"summary",
    }
    for field, value in req.model_dump(exclude_none=True).items():
        changes[mapping[field]]=value
    if not changes:
        raise HTTPException(400, "At least one incident property is required")
    data=await defender().update_incident(incident_id, changes)
    db.upsert_incidents([data])
    return data

@app.post("/api/incidents/{incident_id}/comments")
async def comment_incident(incident_id: str, req: IncidentCommentRequest):
    data=await defender().incident_comment(incident_id, req.comment)
    return data

@app.get("/api/incidents/{incident_id}/report", response_class=PlainTextResponse)
def incident_report(incident_id: str):
    incident=db.incident(incident_id)
    if not incident:
        raise HTTPException(404, "Incident not found")
    return build_incident_report(
        incident,
        db.investigations(incident_id),
        db.evidence(incident_id),
        db.response_actions(incident_id),
    )

@app.post("/api/incidents/{incident_id}/evidence")
def add_evidence(incident_id: str, req: EvidenceRequest):
    if not db.incident(incident_id):
        raise HTTPException(404, "Incident not found in local cache")
    evidence_id=db.add_evidence(
        incident_id,
        req.source_type,
        req.title,
        req.data,
        req.source_id,
    )
    return {"id":evidence_id,"incident_id":incident_id}

@app.post("/api/hunting")
async def hunting(req: HuntingRequest):
    data=await defender().hunting_query(req.query,req.timespan)
    investigation_id=db.save_investigation(req.incident_id,req.query,data)
    if req.incident_id:
        db.add_evidence(
            req.incident_id,
            "advanced_hunting",
            "Advanced Hunting query result",
            {"query":req.query,"timespan":req.timespan,"result":data},
            str(investigation_id),
        )
    return {"investigation_id":investigation_id,"result":data}

@app.get("/api/machines")
async def machines(limit: int = 100):
    data=await defender().machines(limit)
    return data

@app.post("/api/response/isolate")
async def isolate(req: IsolateRequest):
    try:
        result=await defender().isolate_machine(req.machine_id,req.comment,req.isolation_type)
    except ValueError as exc:
        raise HTTPException(400,str(exc)) from exc
    action_id=db.save_response_action(
        req.incident_id,
        req.machine_id,
        "Isolate",
        result.get("status"),
        req.model_dump(),
        result,
    )
    if req.incident_id:
        db.add_evidence(
            req.incident_id,
            "defender_response",
            "Machine isolation action",
            result,
            str(action_id),
        )
    return {"action_id":action_id,"result":result}

@app.post("/api/response/unisolate")
async def unisolate(req: MachineActionRequest):
    result=await defender().unisolate_machine(req.machine_id,req.comment)
    action_id=db.save_response_action(
        req.incident_id,
        req.machine_id,
        "Unisolate",
        result.get("status"),
        req.model_dump(),
        result,
    )
    if req.incident_id:
        db.add_evidence(
            req.incident_id,
            "defender_response",
            "Machine release from isolation action",
            result,
            str(action_id),
        )
    return {"action_id":action_id,"result":result}

@app.post("/api/telemetry")
def ingest(req: IngestRequest):
    count=db.ingest_events(req.table,req.events)
    findings=detect(req.events,req.table)
    return {"ingested":count,"detections":findings}

@app.get("/api/telemetry")
def telemetry(table: str | None = None, limit: int = 500):
    return {"value":db.telemetry(table, min(max(limit,1),5000))}

@app.get("/api/detections/rules")
def detection_rules():
    return {"value":[{k:v for k,v in r.items() if k!="match"} for r in RULES]}

@app.get("/api/response/actions")
def response_actions(incident_id: str | None = None, limit: int = 100):
    return {"value":db.response_actions(incident_id, min(max(limit,1),500))}
