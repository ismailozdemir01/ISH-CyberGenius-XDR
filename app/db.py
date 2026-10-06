import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS incidents (
  id TEXT PRIMARY KEY, name TEXT NOT NULL, severity TEXT, status TEXT, classification TEXT,
  determination TEXT, created_time TEXT, last_update_time TEXT, assigned_to TEXT,
  raw_json TEXT NOT NULL, synced_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS telemetry (
  id INTEGER PRIMARY KEY AUTOINCREMENT, table_name TEXT NOT NULL, timestamp TEXT,
  device_id TEXT, device_name TEXT, action_type TEXT, event_json TEXT NOT NULL, ingested_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_telemetry_table_ts ON telemetry(table_name, timestamp);
CREATE INDEX IF NOT EXISTS idx_telemetry_device ON telemetry(device_name);
CREATE TABLE IF NOT EXISTS investigations (
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, query TEXT NOT NULL,
  result_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_investigations_incident ON investigations(incident_id, created_at);
CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT NOT NULL, source_type TEXT NOT NULL,
  source_id TEXT, title TEXT NOT NULL, data_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_evidence_incident ON evidence(incident_id, created_at);
CREATE TABLE IF NOT EXISTS response_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id TEXT, machine_id TEXT NOT NULL, action TEXT NOT NULL,
  status TEXT, request_json TEXT NOT NULL, result_json TEXT NOT NULL, created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_response_incident ON response_actions(incident_id, created_at);
CREATE TABLE IF NOT EXISTS correlations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id TEXT,
  rule_id TEXT NOT NULL,
  title TEXT NOT NULL,
  severity TEXT NOT NULL,
  score INTEGER NOT NULL,
  confidence TEXT NOT NULL,
  device TEXT,
  first_timestamp TEXT,
  last_timestamp TEXT,
  techniques_json TEXT NOT NULL,
  evidence_json TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_correlations_incident ON correlations(incident_id, created_at);
CREATE INDEX IF NOT EXISTS idx_correlations_device ON correlations(device, created_at);
CREATE TABLE IF NOT EXISTS licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_key TEXT NOT NULL UNIQUE,
  product_permalink TEXT NOT NULL,
  email TEXT,
  order_number TEXT,
  full_name TEXT,
  plan TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  price TEXT,
  currency TEXT,
  variants TEXT,
  quantity INTEGER NOT NULL DEFAULT 1,
  uses INTEGER NOT NULL DEFAULT 0,
  seats INTEGER,
  raw_json TEXT NOT NULL,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_licenses_email ON licenses(email);
CREATE INDEX IF NOT EXISTS idx_licenses_order ON licenses(order_number);
CREATE INDEX IF NOT EXISTS idx_licenses_status ON licenses(status);
CREATE TABLE IF NOT EXISTS license_activations (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id TEXT NOT NULL,
  device_hash TEXT NOT NULL,
  activated_at TEXT NOT NULL,
  last_seen_at TEXT NOT NULL,
  UNIQUE(license_id, device_hash)
);
CREATE INDEX IF NOT EXISTS idx_license_activations_license ON license_activations(license_id);
CREATE TABLE IF NOT EXISTS issued_licenses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  license_id TEXT NOT NULL UNIQUE,
  token TEXT NOT NULL,
  email TEXT,
  order_number TEXT,
  created_at TEXT NOT NULL
);
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
                    ON CONFLICT(id) DO UPDATE SET name=excluded.name,severity=excluded.severity,status=excluded.status,
                    classification=excluded.classification,determination=excluded.determination,created_time=excluded.created_time,
                    last_update_time=excluded.last_update_time,assigned_to=excluded.assigned_to,raw_json=excluded.raw_json,synced_at=excluded.synced_at""",
                    (incident_id, x.get("displayName", x.get("incidentName", "")), x.get("severity"), x.get("status"),
                     x.get("classification"), x.get("determination"), x.get("createdDateTime", x.get("createdTime")),
                     x.get("lastUpdateDateTime", x.get("lastUpdateTime")), x.get("assignedTo"), json.dumps(x), now),
                )
        return len(incidents)

    def incident(self, incident_id: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute("SELECT * FROM incidents WHERE id=?", (incident_id,)).fetchone()
        if not row:
            return None
        d = dict(row); d["raw"] = json.loads(d.pop("raw_json")); return d

    def list_incidents(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM incidents ORDER BY COALESCE(last_update_time, created_time) DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def ingest_events(self, table_name: str, events: list[dict[str, Any]]) -> int:
        now = utcnow()
        with self.connect() as con:
            con.executemany(
                "INSERT INTO telemetry(table_name,timestamp,device_id,device_name,action_type,event_json,ingested_at) VALUES(?,?,?,?,?,?,?)",
                [(table_name, e.get("Timestamp"), e.get("DeviceId"), e.get("DeviceName"), e.get("ActionType"), json.dumps(e), now) for e in events],
            )
        return len(events)

    def telemetry(self, table_name: str | None = None, limit: int = 500) -> list[dict[str, Any]]:
        sql = "SELECT * FROM telemetry"; args: list[Any] = []
        if table_name:
            sql += " WHERE table_name=?"; args.append(table_name)
        sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
        with self.connect() as con:
            rows = con.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r); d["event"] = json.loads(d.pop("event_json")); out.append(d)
        return out

    def save_investigation(self, incident_id: str | None, query: str, result: dict[str, Any]) -> int:
        with self.connect() as con:
            cur = con.execute("INSERT INTO investigations(incident_id,query,result_json,created_at) VALUES(?,?,?,?)", (incident_id, query, json.dumps(result), utcnow()))
            return int(cur.lastrowid)

    def investigations(self, incident_id: str, limit: int = 50) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM investigations WHERE incident_id=? ORDER BY id DESC LIMIT ?", (incident_id, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r); d["result"] = json.loads(d.pop("result_json")); out.append(d)
        return out

    def add_evidence(self, incident_id: str, source_type: str, title: str, data: dict[str, Any], source_id: str | None = None) -> int:
        with self.connect() as con:
            cur = con.execute("INSERT INTO evidence(incident_id,source_type,source_id,title,data_json,created_at) VALUES(?,?,?,?,?,?)",
                              (incident_id, source_type, source_id, title, json.dumps(data), utcnow()))
            return int(cur.lastrowid)

    def evidence(self, incident_id: str, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute("SELECT * FROM evidence WHERE incident_id=? ORDER BY id DESC LIMIT ?", (incident_id, limit)).fetchall()
        out = []
        for r in rows:
            d = dict(r); d["data"] = json.loads(d.pop("data_json")); out.append(d)
        return out

    def save_response_action(self, incident_id: str | None, machine_id: str, action: str, status: str | None,
                            request: dict[str, Any], result: dict[str, Any]) -> int:
        with self.connect() as con:
            cur = con.execute("INSERT INTO response_actions(incident_id,machine_id,action,status,request_json,result_json,created_at) VALUES(?,?,?,?,?,?,?)",
                              (incident_id, machine_id, action, status, json.dumps(request), json.dumps(result), utcnow()))
            return int(cur.lastrowid)

    def response_actions(self, incident_id: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM response_actions"; args: list[Any] = []
        if incident_id:
            sql += " WHERE incident_id=?"; args.append(incident_id)
        sql += " ORDER BY id DESC LIMIT ?"; args.append(limit)
        with self.connect() as con:
            rows = con.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r); d["request"] = json.loads(d.pop("request_json")); d["result"] = json.loads(d.pop("result_json")); out.append(d)
        return out

    def upsert_gumroad_license(self, sale: dict[str, Any], raw_payload: dict[str, Any]) -> dict[str, Any]:
        license_key = sale["license_key"]
        now = utcnow()
        try:
            quantity = max(1, int(sale.get("quantity") or 1))
        except (TypeError, ValueError):
            quantity = 1
        plan = sale.get("variants") or "default"
        with self.connect() as con:
            con.execute(
                """INSERT INTO licenses
                (license_key,product_permalink,email,order_number,full_name,plan,status,price,currency,variants,quantity,raw_json,created_at,updated_at)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(license_key) DO UPDATE SET
                  product_permalink=excluded.product_permalink,email=excluded.email,order_number=excluded.order_number,
                  full_name=excluded.full_name,plan=excluded.plan,price=excluded.price,currency=excluded.currency,
                  variants=excluded.variants,quantity=excluded.quantity,raw_json=excluded.raw_json,updated_at=excluded.updated_at""",
                (license_key, sale["product_permalink"], sale.get("email"), sale.get("order_number"), sale.get("full_name"),
                 plan, "active", sale.get("price"), sale.get("currency"), sale.get("variants"), quantity,
                 json.dumps(raw_payload), now, now),
            )
            row = con.execute(
                "SELECT id,license_key,product_permalink,email,order_number,full_name,plan,status,price,currency,variants,quantity,uses,seats,created_at,updated_at FROM licenses WHERE license_key=?",
                (license_key,),
            ).fetchone()
        return dict(row)

    def license(self, license_key: str) -> dict[str, Any] | None:
        with self.connect() as con:
            row = con.execute(
                "SELECT id,license_key,product_permalink,email,order_number,full_name,plan,status,price,currency,variants,quantity,uses,seats,created_at,updated_at FROM licenses WHERE license_key=?",
                (license_key,),
            ).fetchone()
        return dict(row) if row else None

    def licenses(self, limit: int = 100) -> list[dict[str, Any]]:
        with self.connect() as con:
            rows = con.execute(
                "SELECT id,license_key,product_permalink,email,order_number,full_name,plan,status,price,currency,variants,quantity,uses,seats,created_at,updated_at FROM licenses ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def save_issued_license(self, license_id: str, token: str, email: str = "", order_number: str = "") -> dict[str, Any]:
        now = utcnow()
        with self.connect() as con:
            con.execute(
                """INSERT INTO issued_licenses(license_id,token,email,order_number,created_at)
                VALUES(?,?,?,?,?)
                ON CONFLICT(license_id) DO UPDATE SET token=excluded.token,email=excluded.email,order_number=excluded.order_number""",
                (license_id, token, email, order_number, now),
            )
            row = con.execute("SELECT id,license_id,email,order_number,created_at FROM issued_licenses WHERE license_id=?", (license_id,)).fetchone()
        return dict(row)

    def issued_license_token(self, license_id: str) -> str | None:
        with self.connect() as con:
            row = con.execute("SELECT token FROM issued_licenses WHERE license_id=?", (license_id,)).fetchone()
        return str(row["token"]) if row else None

    def activate_license(self, license_id: str, device_hash: str, max_activations: int) -> dict[str, Any]:
        now = utcnow()
        with self.connect() as con:
            row = con.execute("SELECT * FROM license_activations WHERE license_id=? AND device_hash=?", (license_id, device_hash)).fetchone()
            if row:
                con.execute("UPDATE license_activations SET last_seen_at=? WHERE id=?", (now, row["id"]))
                return {"activated": True, "new_activation": False, "activation_count": con.execute("SELECT COUNT(*) FROM license_activations WHERE license_id=?", (license_id,)).fetchone()[0]}
            count = con.execute("SELECT COUNT(*) FROM license_activations WHERE license_id=?", (license_id,)).fetchone()[0]
            if count >= max_activations:
                raise ValueError("Activation limit reached")
            con.execute("INSERT INTO license_activations(license_id,device_hash,activated_at,last_seen_at) VALUES(?,?,?,?)", (license_id, device_hash, now, now))
            return {"activated": True, "new_activation": True, "activation_count": count + 1}

    def license_activation_count(self, license_id: str) -> int:
        with self.connect() as con:
            return int(con.execute("SELECT COUNT(*) FROM license_activations WHERE license_id=?", (license_id,)).fetchone()[0])

    def save_correlations(self, incident_id: str | None, findings: list[dict[str, Any]]) -> int:
        if not findings:
            return 0
        with self.connect() as con:
            con.executemany(
                "INSERT INTO correlations(incident_id,rule_id,title,severity,score,confidence,device,first_timestamp,last_timestamp,techniques_json,evidence_json,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
                [(incident_id, f["rule_id"], f["title"], f["severity"], int(f["score"]), f["confidence"], f.get("device"),
                  f.get("first_timestamp"), f.get("last_timestamp"), json.dumps(f.get("techniques", [])), json.dumps(f.get("evidence", [])), utcnow()) for f in findings],
            )
        return len(findings)

    def correlations(self, incident_id: str | None = None, device: str | None = None, limit: int = 100) -> list[dict[str, Any]]:
        sql = "SELECT * FROM correlations"; args: list[Any] = []; clauses = []
        if incident_id:
            clauses.append("incident_id=?"); args.append(incident_id)
        if device:
            clauses.append("device=?"); args.append(device)
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY score DESC, id DESC LIMIT ?"; args.append(limit)
        with self.connect() as con:
            rows = con.execute(sql, args).fetchall()
        out = []
        for r in rows:
            d = dict(r); d["techniques"] = json.loads(d.pop("techniques_json")); d["evidence"] = json.loads(d.pop("evidence_json")); out.append(d)
        return out
