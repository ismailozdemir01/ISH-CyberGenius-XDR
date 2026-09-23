from app.analytics import build_entity_graph, calculate_risk, summarize


def event(table, device="host-01", timestamp="2026-09-23T10:00:00+00:00", **data):
    return {"table_name": table, "device_name": device, "timestamp": timestamp, "event": {"DeviceName": device, "Timestamp": timestamp, **data}}


def test_entity_graph_extracts_device_process_ip_and_hash():
    rows = [event("DeviceProcessEvents", FileName="powershell.exe", SHA256="a" * 64, AccountName="alice")]
    graph = build_entity_graph(rows)
    kinds = {node["kind"] for node in graph["nodes"]}
    assert {"device", "process", "hash", "user"}.issubset(kinds)
    assert graph["event_count"] == 1


def test_risk_score_uses_correlation_and_multi_technique_chain():
    incident = {"severity": "high"}
    correlations = [{"score": 95, "techniques": ["T1059.001", "T1021.001"], "severity": "Critical"}]
    result = calculate_risk(incident, correlations, [{"id": 1}], [])
    assert result["score"] == 100
    assert result["band"] == "critical"
    assert "multi_technique_chain" in {x["name"] for x in result["factors"]}


def test_summary_counts_telemetry_and_attack_techniques():
    rows = [event("DeviceProcessEvents"), event("DeviceNetworkEvents", device="host-02")]
    correlations = [{"severity": "High", "techniques": ["T1059.001"]}, {"severity": "Critical", "techniques": ["T1059.001", "T1021.001"]}]
    result = summarize(rows, correlations)
    assert result["telemetry_events"] == 2
    assert result["devices"] == 2
    assert result["attack_techniques"]["T1059.001"] == 2
