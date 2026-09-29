from __future__ import annotations

from bisect import bisect_left, bisect_right
from datetime import datetime, timedelta, timezone
from typing import Any


def _parse_time(value: Any) -> datetime | None:
    if not value:
        return None
    text = str(value).strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _event(row: dict[str, Any]) -> dict[str, Any]:
    event = dict(row.get("event") or {})
    event["_table"] = row.get("table_name")
    event["_timestamp"] = row.get("timestamp") or event.get("Timestamp")
    event["_device"] = row.get("device_name") or event.get("DeviceName")
    event["_device_id"] = row.get("device_id") or event.get("DeviceId")
    event["_parsed_timestamp"] = _parse_time(event["_timestamp"])
    return event


def _device_key(event: dict[str, Any]) -> str:
    return str(event.get("_device") or event.get("_device_id") or "").lower()


def _nearby(index: dict[str, tuple[list[float], list[dict[str, Any]]]], event: dict[str, Any], window_seconds: float) -> list[dict[str, Any]]:
    ts = event.get("_parsed_timestamp")
    if not ts:
        return []
    bucket = index.get(_device_key(event))
    if not bucket:
        return []
    times, values = bucket
    epoch = ts.timestamp()
    start = bisect_left(times, epoch - window_seconds)
    end = bisect_right(times, epoch + window_seconds)
    return values[start:end]


def _time_index(events: list[dict[str, Any]]) -> dict[str, tuple[list[float], list[dict[str, Any]]]]:
    grouped: dict[str, list[dict[str, Any]]] = {}
    for event in events:
        grouped.setdefault(_device_key(event), []).append(event)
    result: dict[str, tuple[list[float], list[dict[str, Any]]]] = {}
    for device, values in grouped.items():
        values.sort(key=lambda x: x["_parsed_timestamp"].timestamp())
        result[device] = ([x["_parsed_timestamp"].timestamp() for x in values], values)
    return result


def correlate(rows: list[dict[str, Any]], window_minutes: int = 15, device_name: str | None = None) -> list[dict[str, Any]]:
    window = timedelta(minutes=window_minutes)
    window_seconds = window.total_seconds()
    events = [_event(row) for row in rows]
    events = [e for e in events if e.get("_parsed_timestamp")]
    if device_name:
        wanted = device_name.lower()
        events = [e for e in events if str(e.get("_device", "")).lower() == wanted]

    process_events = [e for e in events if e.get("_table") == "DeviceProcessEvents"]
    network_events = [e for e in events if e.get("_table") == "DeviceNetworkEvents"]
    network_index = _time_index(network_events)
    process_index = _time_index(process_events)
    findings: list[dict[str, Any]] = []

    for proc in process_events:
        command = str(proc.get("ProcessCommandLine", ""))
        filename = str(proc.get("FileName", "")).lower()
        initiating = str(proc.get("InitiatingProcessFileName", "")).lower()
        if (filename != "powershell.exe" and initiating != "powershell.exe") or ("-enc" not in command.lower() and "-encodedcommand" not in command.lower()):
            continue
        ts = proc["_parsed_timestamp"]
        device = proc.get("_device") or proc.get("_device_id") or "unknown"
        findings.append({
            "rule_id": "CORR-PS-ENC-001", "title": "Encoded PowerShell execution", "severity": "High",
            "score": 60, "confidence": "high", "device": device, "techniques": ["T1059.001"],
            "first_timestamp": ts.isoformat(), "last_timestamp": ts.isoformat(), "evidence": [proc],
        })
        nearby_network = _nearby(network_index, proc, window_seconds)
        if nearby_network:
            timestamps = [ts, *[x["_parsed_timestamp"] for x in nearby_network]]
            findings.append({
                "rule_id": "CORR-PS-NET-002", "title": "Encoded PowerShell followed by network activity", "severity": "High",
                "score": 80, "confidence": "high", "device": device, "techniques": ["T1059.001"],
                "first_timestamp": min(timestamps).isoformat(), "last_timestamp": max(timestamps).isoformat(),
                "evidence": [proc, *nearby_network[:20]],
            })

    for net in network_events:
        if str(net.get("RemotePort", "")) != "3389":
            continue
        ts = net["_parsed_timestamp"]
        device = net.get("_device") or net.get("_device_id")
        if not device:
            continue
        nearby_process = _nearby(process_index, net, window_seconds)
        if not nearby_process:
            continue
        timestamps = [ts, *[x["_parsed_timestamp"] for x in nearby_process]]
        findings.append({
            "rule_id": "CORR-RDP-PROC-003", "title": "RDP network activity correlated with process execution", "severity": "Medium",
            "score": 45, "confidence": "medium", "device": device, "techniques": ["T1021.001"],
            "first_timestamp": min(timestamps).isoformat(), "last_timestamp": max(timestamps).isoformat(),
            "evidence": [net, *nearby_process[:20]],
        })

    base = list(findings)
    for left in base:
        for right in base:
            if left is right or str(left["device"]).lower() != str(right["device"]).lower():
                continue
            if {left["rule_id"], right["rule_id"]} != {"CORR-PS-ENC-001", "CORR-RDP-PROC-003"}:
                continue
            left_ts = _parse_time(left["first_timestamp"])
            right_ts = _parse_time(right["first_timestamp"])
            if not left_ts or not right_ts or abs(left_ts - right_ts) > window:
                continue
            findings.append({
                "rule_id": "CORR-PS-RDP-004", "title": "Encoded PowerShell and RDP activity correlated on the same device",
                "severity": "Critical", "score": 95, "confidence": "high", "device": left["device"],
                "techniques": ["T1059.001", "T1021.001"],
                "first_timestamp": min(left_ts, right_ts).isoformat(), "last_timestamp": max(left_ts, right_ts).isoformat(),
                "evidence": (left["evidence"] + right["evidence"])[:40],
            })

    unique: dict[tuple[str, str, str | None, str | None], dict[str, Any]] = {}
    for finding in findings:
        key = (finding["rule_id"], str(finding["device"]), finding.get("first_timestamp"), finding.get("last_timestamp"))
        unique[key] = finding
    return sorted(unique.values(), key=lambda x: (x.get("score", 0), x.get("last_timestamp") or ""), reverse=True)
