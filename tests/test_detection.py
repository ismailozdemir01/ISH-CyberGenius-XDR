from app.detection import detect

def test_powershell_detection():
    events=[{
        "Timestamp":"2026-09-22T10:00:00Z",
        "DeviceName":"host01",
        "FileName":"powershell.exe",
        "ProcessCommandLine":"powershell.exe -NoProfile",
    }]
    out=detect(events,"DeviceProcessEvents")
    assert any(x["rule_id"]=="PROC-POWERSHELL-001" for x in out)

def test_encoded_command_is_high():
    events=[{
        "FileName":"powershell.exe",
        "ProcessCommandLine":"powershell.exe -EncodedCommand AAA",
    }]
    out=detect(events,"DeviceProcessEvents")
    assert any(x["rule_id"]=="PROC-SCRIPT-002" and x["severity"]=="High" for x in out)

def test_rdp_rule():
    out=detect([{"RemotePort":3389}],"DeviceNetworkEvents")
    assert out[0]["rule_id"]=="NET-RDP-003"
