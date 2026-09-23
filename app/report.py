from typing import Any

def _lines(items: list[str]) -> str:
    return "\n".join(items) if items else "- None"

def build_incident_report(
    incident: dict[str, Any],
    investigations: list[dict[str, Any]],
    evidence: list[dict[str, Any]],
    response_actions: list[dict[str, Any]],
    correlations: list[dict[str, Any]] | None = None,
) -> str:
    lines = [
        f"# Incident Report: {incident.get('name') or incident.get('id')}", "",
        "## Incident",
        f"- ID: {incident.get('id')}", f"- Severity: {incident.get('severity')}",
        f"- Status: {incident.get('status')}", f"- Classification: {incident.get('classification')}",
        f"- Determination: {incident.get('determination')}", f"- Assigned to: {incident.get('assigned_to')}",
        f"- Created: {incident.get('created_time')}", f"- Last update: {incident.get('last_update_time')}", "",
        "## Behavioral Correlations",
    ]
    correlation_lines = [
        f"- {item.get('first_timestamp') or item.get('created_at')} — {item['severity']} ({item['score']}) — {item['title']} — device={item.get('device')} — techniques={','.join(item.get('techniques', []))}"
        for item in (correlations or [])
    ]
    lines.append(_lines(correlation_lines))
    lines.extend(["", "## Evidence"])
    lines.append(_lines([f"- **{item['title']}** ({item['source_type']}) — {item.get('source_id') or 'n/a'}" for item in evidence]))
    lines.extend(["", "## Investigations"])
    lines.append(_lines([f"- {item['created_at']} — {item['query']}" for item in investigations]))
    lines.extend(["", "## Response Actions"])
    lines.append(_lines([f"- {item['created_at']} — {item['action']} on {item['machine_id']} — {item.get('status') or 'unknown'}" for item in response_actions]))
    return "\n".join(lines) + "\n"
