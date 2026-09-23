from app.correlation import correlate
from app.db import Database


def row(table, timestamp, device, event):
    return {
        "table_name": table,
        "timestamp": timestamp,
        "device_name": device,
        "device_id": "device-1",
        "event": event,
    }


def test_encoded_powershell_and_rdp_correlate():
    rows = [
        row("DeviceProcessEvents", "2026-09-23T08:00:00Z", "host01", {
            "Timestamp": "2026-09-23T08:00:00Z",
            "DeviceName": "host01",
            "FileName": "powershell.exe",
            "ProcessCommandLine": "powershell.exe -EncodedCommand AAA",
        }),
        row("DeviceNetworkEvents", "2026-09-23T08:06:00Z", "host01", {
            "Timestamp": "2026-09-23T08:06:00Z",
            "DeviceName": "host01",
            "RemotePort": "3389",
            "RemoteIP": "10.0.0.20",
        }),
    ]
    findings = correlate(rows)
    rule_ids = {x["rule_id"] for x in findings}
    assert "CORR-PS-ENC-001" in rule_ids
    assert "CORR-RDP-PROC-003" in rule_ids
    assert "CORR-PS-RDP-004" in rule_ids
    combined = next(x for x in findings if x["rule_id"] == "CORR-PS-RDP-004")
    assert combined["score"] == 95
    assert combined["techniques"] == ["T1059.001", "T1021.001"]


def test_correlation_persistence(tmp_path):
    db = Database(str(tmp_path / "xdr.db"))
    db.upsert_incidents([{"id": "inc-1", "displayName": "Test", "severity": "high", "status": "active"}])
    findings = [{
        "rule_id": "CORR-PS-ENC-001",
        "title": "Encoded PowerShell execution",
        "severity": "High",
        "score": 60,
        "confidence": "high",
        "device": "host01",
        "techniques": ["T1059.001"],
        "first_timestamp": "2026-09-23T08:00:00+00:00",
        "last_timestamp": "2026-09-23T08:00:00+00:00",
        "evidence": [{"FileName": "powershell.exe"}],
    }]
    assert db.save_correlations("inc-1", findings) == 1
    saved = db.correlations("inc-1")
    assert saved[0]["rule_id"] == "CORR-PS-ENC-001"
    assert saved[0]["techniques"] == ["T1059.001"]
