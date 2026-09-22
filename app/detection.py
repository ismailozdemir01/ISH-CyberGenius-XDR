from typing import Any

RULES = [
    {
        "id":"PROC-POWERSHELL-001",
        "table":"DeviceProcessEvents",
        "title":"PowerShell process activity",
        "severity":"Medium",
        "match":lambda e: str(e.get("FileName","")).lower()=="powershell.exe"
            or str(e.get("InitiatingProcessFileName","")).lower()=="powershell.exe",
    },
    {
        "id":"PROC-SCRIPT-002",
        "table":"DeviceProcessEvents",
        "title":"Script interpreter with encoded command",
        "severity":"High",
        "match":lambda e: "-enc" in str(e.get("ProcessCommandLine","")).lower()
            or "-encodedcommand" in str(e.get("ProcessCommandLine","")).lower(),
    },
    {
        "id":"NET-RDP-003",
        "table":"DeviceNetworkEvents",
        "title":"RDP connection telemetry",
        "severity":"Low",
        "match":lambda e: str(e.get("RemotePort",""))=="3389",
    },
]

def detect(events: list[dict[str, Any]], table_name: str) -> list[dict[str, Any]]:
    findings=[]
    for rule in RULES:
        if rule["table"] != table_name:
            continue
        for event in events:
            if rule["match"](event):
                findings.append({
                    "rule_id":rule["id"],
                    "title":rule["title"],
                    "severity":rule["severity"],
                    "table":table_name,
                    "event":event,
                })
    return findings
