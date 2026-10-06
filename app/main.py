from pathlib import Path
from typing import Any, Literal
from secrets import compare_digest
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, ConfigDict, Field
from starlette.middleware.gzip import GZipMiddleware
from .analytics import build_entity_graph, calculate_risk, summarize
from .config import settings
from .db import Database
from .defender import DefenderClient
from .detection import detect, RULES
from .correlation import correlate
from .report import build_incident_report
from .translator import TranslatorClient
from .licensing import GumroadClient, GumroadError, gumroad_sale_fields

app=FastAPI(title=settings.app_name, version="1.3.0")
db=Database(settings.database_path)
app.add_middleware(GZipMiddleware, minimum_size=1000)

@app.middleware("http")
async def security_headers(request: Request, call_next):
    if request.url.path.startswith("/api/"):
        if not settings.api_key:
            return PlainTextResponse("API authentication is not configured.", status_code=503)
        auth=request.headers.get("Authorization","")
        if not auth.startswith("Bearer ") or not compare_digest(auth[7:], settings.api_key):
            return PlainTextResponse("Unauthorized", status_code=401, headers={"WWW-Authenticate":"Bearer"})
    response=await call_next(request)
    response.headers["X-Content-Type-Options"]="nosniff"
    response.headers["X-Frame-Options"]="DENY"
    response.headers["Referrer-Policy"]="no-referrer"
    response.headers["Permissions-Policy"]="camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"]="no-store" if request.url.path.startswith("/api/") else "no-cache"
    return response

def defender() -> DefenderClient:
    if not settings.graph_configured:
        raise HTTPException(503,"Microsoft credentials are not configured. Set TENANT_ID, CLIENT_ID and CLIENT_SECRET.")
    return DefenderClient(settings.tenant_id,settings.client_id,settings.client_secret,settings.graph_base_url,settings.request_timeout,settings.defender_api_base_url)

class HuntingRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    query:str=Field(min_length=1,max_length=20000); timespan:str|None=Field(default=None,max_length=100); incident_id:str|None=Field(default=None,max_length=200)
class IngestRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    table:str=Field(pattern=r"^[A-Za-z][A-Za-z0-9_]{1,127}$"); events:list[dict[str,Any]]=Field(min_length=1,max_length=10000)
class CorrelationRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    incident_id:str|None=Field(default=None,max_length=200); device_name:str|None=Field(default=None,max_length=500); window_minutes:int=Field(default=15,ge=1,le=240); telemetry_limit:int=Field(default=5000,ge=1,le=5000)
class IncidentUpdateRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    assigned_to:str|None=Field(default=None,max_length=320); classification:str|None=Field(default=None,max_length=80); determination:str|None=Field(default=None,max_length=80); custom_tags:list[str]|None=Field(default=None,max_length=50); description:str|None=Field(default=None,max_length=10000); display_name:str|None=Field(default=None,max_length=500); severity:Literal["unknown","informational","low","medium","high","unknownFutureValue"]|None=None; status:Literal["active","resolved","redirected"]|None=None; resolving_comment:str|None=Field(default=None,max_length=5000); summary:str|None=Field(default=None,max_length=10000)
class IncidentCommentRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    comment:str=Field(min_length=1,max_length=10000)
class EvidenceRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    source_type:str=Field(min_length=1,max_length=100); source_id:str|None=Field(default=None,max_length=500); title:str=Field(min_length=1,max_length=500); data:dict[str,Any]
class MachineActionRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    incident_id:str|None=Field(default=None,max_length=200); machine_id:str=Field(min_length=1,max_length=200); comment:str=Field(min_length=1,max_length=2000)
class IsolateRequest(MachineActionRequest):
    isolation_type:Literal["Full","Selective","UnManagedDevice"]="Full"

class TranslationRequest(BaseModel):
    model_config=ConfigDict(extra="forbid")
    text:str=Field(min_length=1,max_length=20000)
    target_language:str=Field(pattern=r"^[A-Za-z]{2,3}(?:-[A-Za-z]{2,4})?$")
    source_language:str|None=Field(default=None,max_length=20)

def translator() -> TranslatorClient:
    if not settings.translator_configured:
        raise HTTPException(503,"Microsoft Translator is not configured. Set TRANSLATOR_KEY.")
    return TranslatorClient(settings.translator_endpoint,settings.translator_key,settings.translator_region,settings.request_timeout)

@app.get("/health")
def health(): return {"status":"ok","graph_configured":settings.graph_configured,"translator_configured":settings.translator_configured,"api_auth_configured":bool(settings.api_key),"database":settings.database_path,"version":app.version}
@app.get("/ready")
def ready():
    try: db.telemetry(limit=1); return {"status":"ready","graph_configured":settings.graph_configured,"api_auth_configured":bool(settings.api_key)}
    except Exception as exc: raise HTTPException(503,f"Database unavailable: {exc}") from exc
@app.get("/api/overview")
def overview(limit:int=5000):
    rows=db.telemetry(limit=min(max(limit,1),5000)); correlations=db.correlations(limit=500)
    return summarize(rows,correlations)
@app.get("/api/incidents")
async def list_incidents(limit:int=100,refresh:bool=True):
    limit=min(max(limit,1),100)
    if refresh and settings.graph_configured: data=await defender().incidents(limit); db.upsert_incidents(data.get("value",[]))
    return {"value":db.list_incidents(limit)}
@app.get("/api/incidents/{incident_id}")
async def get_incident(incident_id:str,refresh:bool=True):
    if refresh and settings.graph_configured: data=await defender().incident(incident_id); db.upsert_incidents([data])
    incident=db.incident(incident_id)
    if not incident: raise HTTPException(404,"Incident not found")
    correlations=db.correlations(incident_id); evidence=db.evidence(incident_id); actions=db.response_actions(incident_id)
    return {"incident":incident,"risk":calculate_risk(incident,correlations,evidence,actions),"investigations":db.investigations(incident_id),"evidence":evidence,"response_actions":actions,"correlations":correlations}
@app.get("/api/incidents/{incident_id}/graph")
def incident_graph(incident_id:str,limit:int=5000):
    if not db.incident(incident_id): raise HTTPException(404,"Incident not found")
    return build_entity_graph(db.telemetry(limit=min(max(limit,1),5000)),db.correlations(incident_id))
@app.get("/api/incidents/{incident_id}/risk")
def incident_risk(incident_id:str):
    incident=db.incident(incident_id)
    if not incident: raise HTTPException(404,"Incident not found")
    return calculate_risk(incident,db.correlations(incident_id),db.evidence(incident_id),db.response_actions(incident_id))
@app.patch("/api/incidents/{incident_id}")
async def update_incident(incident_id:str,req:IncidentUpdateRequest):
    mapping={"assigned_to":"assignedTo","classification":"classification","determination":"determination","custom_tags":"customTags","description":"description","display_name":"displayName","severity":"severity","status":"status","resolving_comment":"resolvingComment","summary":"summary"}; changes={mapping[k]:v for k,v in req.model_dump(exclude_none=True).items()}
    if not changes: raise HTTPException(400,"At least one incident property is required")
    data=await defender().update_incident(incident_id,changes); db.upsert_incidents([data]); return data
@app.post("/api/incidents/{incident_id}/comments")
async def comment_incident(incident_id:str,req:IncidentCommentRequest): return await defender().incident_comment(incident_id,req.comment)
@app.get("/api/incidents/{incident_id}/report",response_class=PlainTextResponse)
def incident_report(incident_id:str):
    incident=db.incident(incident_id)
    if not incident: raise HTTPException(404,"Incident not found")
    return build_incident_report(incident,db.investigations(incident_id),db.evidence(incident_id),db.response_actions(incident_id),db.correlations(incident_id))
@app.post("/api/incidents/{incident_id}/evidence")
def add_evidence(incident_id:str,req:EvidenceRequest):
    if not db.incident(incident_id): raise HTTPException(404,"Incident not found in local cache")
    return {"id":db.add_evidence(incident_id,req.source_type,req.title,req.data,req.source_id),"incident_id":incident_id}
@app.post("/api/translate")
async def translate(req:TranslationRequest):
    detection=await translator().detect(req.text)
    result=await translator().translate(req.text,req.target_language,req.source_language or detection.get("language"))
    return {"source_language":req.source_language or detection.get("language"),"detection":detection,"translation":result}

@app.post("/api/hunting")
async def hunting(req:HuntingRequest):
    data=await defender().hunting_query(req.query,req.timespan); investigation_id=db.save_investigation(req.incident_id,req.query,data)
    if req.incident_id: db.add_evidence(req.incident_id,"advanced_hunting","Advanced Hunting query result",{"query":req.query,"timespan":req.timespan,"result":data},str(investigation_id))
    return {"investigation_id":investigation_id,"result":data}
@app.post("/api/correlate")
def run_correlation(req:CorrelationRequest):
    findings=correlate(db.telemetry(limit=req.telemetry_limit),req.window_minutes,req.device_name); saved=db.save_correlations(req.incident_id,findings)
    if req.incident_id:
        for finding in findings: db.add_evidence(req.incident_id,"behavioral_correlation",finding["title"],finding)
    return {"saved":saved,"findings":findings}
@app.get("/api/correlations")
def list_correlations(incident_id:str|None=None,device_name:str|None=None,limit:int=100): return {"value":db.correlations(incident_id,device_name,min(max(limit,1),500))}
@app.get("/api/timeline/{incident_id}")
def incident_timeline(incident_id:str,limit:int=500):
    if not db.incident(incident_id): raise HTTPException(404,"Incident not found")
    timeline=[]
    for item in db.correlations(incident_id,limit=min(max(limit,1),500)): timeline.append({"type":"correlation","timestamp":item.get("first_timestamp") or item.get("created_at"),"title":item["title"],"severity":item["severity"],"score":item["score"],"techniques":item["techniques"],"data":item})
    for item in db.evidence(incident_id,limit=min(max(limit,1),500)): timeline.append({"type":"evidence","timestamp":item.get("created_at"),"title":item["title"],"severity":None,"score":None,"techniques":[],"data":item})
    timeline.sort(key=lambda x:x.get("timestamp") or "",reverse=True); return {"incident_id":incident_id,"value":timeline[:limit]}
@app.get("/api/machines")
async def machines(limit:int=100): return await defender().machines(min(max(limit,1),10000))
@app.post("/api/response/isolate")
async def isolate(req:IsolateRequest):
    try: result=await defender().isolate_machine(req.machine_id,req.comment,req.isolation_type)
    except ValueError as exc: raise HTTPException(400,str(exc)) from exc
    action_id=db.save_response_action(req.incident_id,req.machine_id,"Isolate",result.get("status"),req.model_dump(),result)
    if req.incident_id: db.add_evidence(req.incident_id,"defender_response","Machine isolation action",result,str(action_id))
    return {"action_id":action_id,"result":result}
@app.post("/api/response/unisolate")
async def unisolate(req:MachineActionRequest):
    result=await defender().unisolate_machine(req.machine_id,req.comment); action_id=db.save_response_action(req.incident_id,req.machine_id,"Unisolate",result.get("status"),req.model_dump(),result)
    if req.incident_id: db.add_evidence(req.incident_id,"defender_response","Machine release from isolation action",result,str(action_id))
    return {"action_id":action_id,"result":result}
@app.post("/api/telemetry")
def ingest(req:IngestRequest):
    count=db.ingest_events(req.table,req.events); return {"ingested":count,"detections":detect(req.events,req.table)}
@app.get("/api/telemetry")
def telemetry(table:str|None=None,limit:int=500): return {"value":db.telemetry(table,min(max(limit,1),5000))}
@app.get("/api/detections/rules")
def detection_rules(): return {"value":[{k:v for k,v in r.items() if k!="match"} for r in RULES]}
@app.get("/api/response/actions")
def response_actions(incident_id:str|None=None,limit:int=100): return {"value":db.response_actions(incident_id,min(max(limit,1),500))}
app.mount("/",StaticFiles(directory=Path(__file__).parent/"static",html=True),name="ui")
