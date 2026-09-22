from typing import Any

def _lines(items: list[str]) -> str:
    return "\n".join(items) if items else "- None"

def build_incident_report(
    incident: dict[str, Any],
    investigations: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    response_actions: list[dict[str, Any]],
) -> str:
    lines = [
        f"# Incident Report: {incident.get('name') or incident.get('id')}",
        "",
        "## Incident",
        f"- ID: {incident.get('id')}",
        f"- Severity: {incident.get('severity')}",
        f"- Status: {incident.get('status')}",
        f"- Classification: {incident.get('classification')}",
        f"- Determination: {incident.get('determination')}",
        f"- Assigned to: {incident.get('assigned_to')}",
        f"- Created: {incident.get('created_time')}",
        f"- Last update: {incident.get('last_update_time')}",
        "",
        "## Evidence",
    ]
    evidence_lines = []
    for item in evidence:
        evidence_lines.append(
            f"- **{item['title']}** ({item['source_type']}) — {item.get('source_id') or 'n/a'}"
        )
    lines.append(_lines(evidence_lines))
    lines.extend(["", "## Investigations"])
    investigation_lines = [
        f"- {item['created_at']} — {item['query']}"
        for item in investigations
    ]
    lines.append(_lines(investigation_lines))
    lines.extend(["", "## Response Actions"])
    action_lines = [
        f"- {item['created_at']} — {item['action']} on {item['machine_id']} — {item.get('status') or 'unknown'}"
        for item in response_actions
    ]
    lines.append(_lines(action_lines))
    return "\n".join(lines) + "\n"
