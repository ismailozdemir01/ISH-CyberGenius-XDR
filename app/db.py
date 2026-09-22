import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  severity TEXT,
  status TEXT,
  classification TEXT,
  determination TEXT,
  created_time TEXT,
  last_update_time TEXT,
  assigned_to TEXT,
  raw_json TEXT NOT NULL,
  synced_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS telemetry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  table_name TEXT NOT NULL,
  timestamp TEXT,
  device_id TEXT,
  device_name TEXT,
  action_type TEXT,
  event_json TEXT NOT NULL,
  ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_telemetry_table_ts ON telemetry(table_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_telemetry_device ON telemetry(device_name);
CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT,
  query TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_investigations_incident ON investigations(incident_id, created_at);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT NOT NULL,
  source_type TEXT NOT NULL,
  source_id TEXT,
  title TEXT NOT NULL,
  data_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id, created_at);
CREATE TABLE IF NOT EXISTS response_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT,
  machine_id TEXT NOT NULL,
  action TEXT NOT NULL,
  status TEXT,
  request_json TEXT NOT NULL,
  result_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_response_incident ON response_actions(incident_id, created_at);
"""

def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()

class Database:
    def __init__(self, path: str):
        self.path = path
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with self.connect() as con:
            con.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        con = sqlite3.connect(self.path)
        con.row_factory = sqlite3.Row
        try:
            yield con
            con.commit()
        finally:
            con.close()

    def upsert_incidents(self, incidents: list[dict[str, Any]]) -> int:
        now = utcnow()
        with self.connect() as con:
            for x in incidents:
                incident_id = str(x.get("id", x.get("incidentId", "")))
                if not incident_id:
                    continue
                con.execute(
                    """INSERT INTO incidents
                    (id,name,severity,status,classification,determination,created_time,last_update_time,assigned_to,raw_json,synced_at)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    ON CONFLICT(id) DO UPDATE SET
                      name=excluded.name,severity=excluded.severity,status=excluded.status,
                      classification=excluded.classification,determination=excluded.determination,
                      created_time=excluded.created_time,last_update_time=excluded.last_update_time,
                      assigned_to=excluded.assigned_to,raw_json=excluded.raw_json,synced_at=excluded.synced_at""",
                    (
                        incident_id,
                        x.get("displayName", x.get("incidentName", "")),
                        x.get("severity"),
                        x.get("status"),
                        x.get("classification"),
                        x.get("determination"),
                        x.get("createdDateTime", x.get("createdTime")),
                        x.get("lastUpdateDateTime", x.get("lastUpdateTime")),
                        x.get("assignedTo"),
                        json.dumps(x),
                        now,
                    ),
                )
        return len(incidents)

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not row:
            return None
        d = dict(row)
        d["raw"] = json.loads(d.pop("raw_json"))
        return d

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM incidents ORDER BY COALESCE(last_update_time, created_time) DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    def ingest_events(self, table_name: str, events: list[dict[str, Any]]) -> int:
        now = utcnow()
        with self.connect() as con:
            con.executemany(
                """INSERT INTO telemetry(table_name,timestamp,device_id,device_name,action_type,event_json,ingested_at)
                VALUES(?,?,?,?,?,?,?)""",
                [
                    (
                        table_name,
                        e.get("Timestamp"),
                        e.get("DeviceId"),
                        e.get("DeviceName"),
                        e.get("ActionType"),
                        json.dumps(e),
                        now,
                    )
                    for e in events
                ],
            )
        return len(events)

    def telemetry(self, table_name: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        sql = "SELECT * FROM telemetry"
        args: list[Any] = []
        if table_name:
            sql += " WHERE table_name=?"
            args.append(table_name)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self.connect() as con:
            rows = con.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["event"] = json.loads(d.pop("event_json"))
            out.append(d)
        return out

    def save_investigation(self, incident_id: str | None, query: str, result: dict[str, Any]) -> int:
        with self.connect() as con:
            cur = con.execute(
                "INSERT INTO investigations(incident_id,query,result_json,created_at) VALUES(?,?,?,?)",
                (incident_id, query, json.dumps(result), utcnow()),
            )
            return int(cur.lastrowid)

    def investigations(self, incident_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM investigations WHERE incident_id=? ORDER BY id DESC LIMIT ?",
                (incident_id, limit),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["result"] = json.loads(d.pop("result_json"))
            out.append(d)
        return out

    def add_evidence(
        self,
        incident_id: str,
        source_type: str,
        title: str,
        data: dict[str, Any],
        source_id: str | None = None,
    ) -> int:
        with self.connect() as con:
            cur = con.execute(
                """INSERT INTO evidence(incident_id,source_type,source_id,title,data_json,created_at)
                   VALUES(?,?,?,?,?,?)""",
                (incident_id, source_type, source_id, title, json.dumps(data), utcnow()),
            )
            return int(cur.lastrowid)

    def evidence(self, incident_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT * FROM evidence WHERE incident_id=? ORDER BY id DESC LIMIT ?",
                (incident_id, limit),
            ).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["data"] = json.loads(d.pop("data_json"))
            out.append(d)
        return out

    def save_response_action(
        self,
        incident_id: str | None,
        machine_id: str,
        action: str,
        status: str | None,
        request: dict[str, Any],
        result: dict[str, Any],
    ) -> int:
        with self.connect() as con:
            cur = con.execute(
                """INSERT INTO response_actions
                   (incident_id,machine_id,action,status,request_json,result_json,created_at)
                   VALUES(?,?,?,?,?,?,?)""",
                (incident_id, machine_id, action, status, json.dumps(request), json.dumps(result), utcnow()),
            )
            return int(cur.lastrowid)

    def response_actions(self, incident_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM response_actions"
        args: list[Any] = []
        if incident_id:
            sql += " WHERE incident_id=?"
            args.append(incident_id)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self.connect() as con:
            rows = con.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["request"] = json.loads(d.pop("request_json"))
            d["result"] = json.loads(d.pop("result_json"))
            out.append(d)
        return out
