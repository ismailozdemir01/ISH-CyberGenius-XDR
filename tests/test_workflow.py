from app.db import Database
from app.report import build_incident_report

def test_investigation_evidence_and_response_persistence(tmp_path):
    db = Database(str(tmp_path / "xdr.db"))
    db.upsert_incidents([{
        "id": "42",
        "displayName": "Test incident",
        "severity": "high",
        "status": "active",
        "classification": "truePositive",
        "determination": "malware",
    }])

    investigation_id = db.save_investigation(
        "42",
        "DeviceProcessEvents | take 1",
        {"Results": [{"DeviceName": "host1"}]},
    )
    evidence_id = db.add_evidence(
        "42",
        "advanced_hunting",
        "Hunting result",
        {"investigation_id": investigation_id},
        str(investigation_id),
    )
    action_id = db.save_response_action(
        "42",
        "machine-1",
        "Isolate",
        "Succeeded",
        {"comment": "contain"},
        {"id": "action-1", "status": "Succeeded"},
    )

    assert evidence_id > 0
    assert action_id > 0
    assert len(db.investigations("42")) == 1
    assert len(db.evidence("42")) == 1
    assert db.response_actions("42")[0]["status"] == "Succeeded"

    report = build_incident_report(
        db.incident("42"),
        db.investigations("42"),
        db.evidence("42"),
        db.response_actions("42"),
    )
    assert "# Incident Report: Test incident" in report
    assert "Hunting result" in report
    assert "Isolate on machine-1" in report
