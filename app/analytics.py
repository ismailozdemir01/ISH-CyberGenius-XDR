from __future__ import annotations

import hashlib
import ipaddress
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any

IP_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32}(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{64})?\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,63}\b")
USER_RE = re.compile(r"(?<![\w.-])(?:[A-Za-z0-9_.-]+\\)?[A-Za-z0-9_.-]{2,64}(?![\w.-])")


def _safe_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def _node(kind: str, value: str) -> dict[str, Any]:
    digest = hashlib.sha256(f"{kind}:{value.lower()}".encode()).hexdigest()[:20]
    return {"id": f"{kind}:{digest}", "kind": kind, "value": value, "label": value}


def _add_edge(edges: dict[tuple[str, str, str], dict[str, Any]], source: dict[str, Any], target: dict[str, Any], relation: str, timestamp: str | None = None) -> None:
    key = (source["id"], target["id"], relation)
    edge = edges.setdefault(key, {"source": source["id"], "target": target["id"], "relation": relation, "count": 0, "timestamps": []})
    edge["count"] += 1
    if timestamp and len(edge["timestamps"]) < 20:
        edge["timestamps"].append(timestamp)


def build_entity_graph(rows: list[dict[str, Any]], correlations: list[dict[str, Any]] | None = None) -> dict[str, Any]:
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    event_count = 0

    def add(kind: str, value: Any) -> dict[str, Any] | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text or len(text) > 512:
            return None
        n = _node(kind, text)
        nodes[n["id"]] = n
        return n

    for row in rows:
        event = dict(row.get("event") or {})
        device = add("device", row.get("device_name") or event.get("DeviceName") or row.get("device_id"))
        if not device:
            continue
        event_count += 1
        timestamp = row.get("timestamp") or event.get("Timestamp")
        user = event.get("AccountName") or event.get("InitiatingProcessAccountName") or event.get("RemoteUserName")
        user_node = add("user", user)
        if user_node:
            _add_edge(edges, user_node, device, "observed-on", timestamp)

        process = event.get("FileName") or event.get("InitiatingProcessFileName")
        process_node = add("process", process)
        if process_node:
            _add_edge(edges, device, process_node, "executed", timestamp)

        for key in ("RemoteIP", "LocalIP", "DestinationIP", "RemoteUrl", "RemoteDomain"):
            value = event.get(key)
            if not value:
                continue
            for candidate in IP_RE.findall(str(value)):
                if _safe_ip(candidate):
                    target = add("ip", candidate)
                    if target:
                        _add_edge(edges, device, target, "communicated-with", timestamp)
            for candidate in DOMAIN_RE.findall(str(value)):
                target = add("domain", candidate.lower())
                if target:
                    _add_edge(edges, device, target, "resolved-or-contacted", timestamp)

        for key in ("SHA1", "SHA256", "MD5", "FileHash"):
            value = event.get(key)
            if value:
                for candidate in HASH_RE.findall(str(value)):
                    target = add("hash", candidate.lower())
                    if target:
                        _add_edge(edges, process_node or device, target, "has-hash", timestamp)

    for finding in correlations or []:
        device = add("device", finding.get("device"))
        if not device:
            continue
        for technique in finding.get("techniques") or []:
            technique_node = add("attack-technique", technique)
            if technique_node:
                _add_edge(edges, device, technique_node, "mapped-to", finding.get("first_timestamp"))

    return {"nodes": list(nodes.values()), "edges": list(edges.values()), "event_count": event_count}


def calculate_risk(
    incident: dict[str, Any],
    correlations: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    response_actions: list[dict[str, Any]],
) -> dict[str, Any]:
    score = 0
    factors: list[dict[str, Any]] = []
    severity_weight = {"unknown": 5, "informational": 5, "low": 15, "medium": 35, "high": 60, "critical": 80}
    severity = str(incident.get("severity") or "unknown").lower()
    base = severity_weight.get(severity, 10)
    score += base
    factors.append({"name": "incident_severity", "weight": base})

    if correlations:
        strongest = max(int(x.get("score") or 0) for x in correlations)
        contribution = min(70, strongest * 0.7)
        score += contribution
        factors.append({"name": "behavioral_correlation", "weight": contribution, "strongest_score": strongest})

    evidence_contribution = min(20, len(evidence) * 2)
    score += evidence_contribution
    factors.append({"name": "evidence_volume", "weight": evidence_contribution, "count": len(evidence)})

    techniques = sorted({t for item in correlations for t in (item.get("techniques") or [])})
    if len(techniques) >= 2:
        score += 10
        factors.append({"name": "multi_technique_chain", "weight": 10, "techniques": techniques})

    score = min(100, round(score))
    band = "critical" if score >= 85 else "high" if score >= 65 else "medium" if score >= 35 else "low"
    return {"score": score, "band": band, "factors": factors, "techniques": techniques, "response_actions": len(response_actions)}


def summarize(rows: list[dict[str, Any]], correlations: list[dict[str, Any]]) -> dict[str, Any]:
    devices = Counter(str(x.get("device_name") or x.get("event", {}).get("DeviceName") or "unknown") for x in rows)
    tables = Counter(str(x.get("table_name") or "unknown") for x in rows)
    severities = Counter(str(x.get("severity") or "unknown") for x in correlations)
    techniques = Counter(t for x in correlations for t in (x.get("techniques") or []))
    return {
        "telemetry_events": len(rows),
        "correlations": len(correlations),
        "devices": len(devices),
        "top_devices": [{"device": k, "events": v} for k, v in devices.most_common(10)],
        "tables": dict(tables),
        "correlation_severity": dict(severities),
        "attack_techniques": dict(techniques),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
