from typing import Any
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field
from .config import settings
from .db import Database
from .defender import DefenderClient
from .detection import detect, RULES

app=FastAPI(title=settings.app_name, version="0.1.0")
db=Database(settings.database_path)

def defender() -> DefenderClient:
    if not settings.graph_configured:
        raise HTTPException(
            503,
            "Microsoft Graph credentials are not configured. Set TENANT_ID, CLIENT_ID and CLIENT_SECRET.",
        )
    return DefenderClient(
        settings.tenant_id,
        settings.client_id,
        settings.client_secret,
        settings.graph_base_url,
        settings.request_timeout,
    )

class HuntingRequest(BaseModel):
    query: str = Field(min_length=1, max_length=20000)
    timespan: str | None = None
    incident_id: str | None = None

class IngestRequest(BaseModel):
    table: str = Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{1,127}$")
    events: list[dict[str, Any]] = Field(min_length=1, max_length=10000)

@app.get("/health")
def health():
    return {
        "status":"ok",
        "graph_configured":settings.graph_configured,
        "database":settings.database_path,
    }

@app.get("/api/incidents")
async def list_incidents(limit: int = 100, refresh: bool = True):
    if refresh and settings.graph_configured:
        data=await defender().incidents(limit)
        values=data.get("value",[])
        db.upsert_incidents(values)
    return {"value":db.list_incidents(limit)}

@app.post("/api/hunting")
async def hunting(req: HuntingRequest):
    data=await defender().hunting_query(req.query,req.timespan)
    db.save_investigation(req.incident_id,req.query,data)
    return data

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
