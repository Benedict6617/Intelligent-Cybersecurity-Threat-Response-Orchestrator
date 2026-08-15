"""
Forensic Timeline Reconstruction
-----------------------------------
Rebuilds a chronological, human-readable narrative of an incident from
its constituent events, mapped against the MITRE ATT&CK kill chain, plus
every automated/analyst action taken in response (from PlaybookRun
action logs). This is the primary artifact for after-action reviews and
regulatory/audit evidence.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from app.core import mitre_attack
from app.models.event import Event
from app.models.incident import Incident
from app.models.playbook import PlaybookRun


def build_timeline(db: Session, incident: Incident) -> dict:
    events = (
        db.query(Event)
        .filter(Event.id.in_(incident.event_ids or []))
        .order_by(Event.occurred_at.asc())
        .all()
    )
    runs = (
        db.query(PlaybookRun)
        .filter(PlaybookRun.incident_id == incident.id)
        .order_by(PlaybookRun.started_at.asc())
        .all()
    )

    timeline_entries = []

    for e in events:
        technique = mitre_attack.get_technique(e.mitre_technique_id) if e.mitre_technique_id else None
        timeline_entries.append({
            "timestamp": e.occurred_at.isoformat(),
            "kind": "detection",
            "source": e.source.value if hasattr(e.source, "value") else e.source,
            "host": e.host,
            "user": e.user,
            "source_ip": e.source_ip,
            "destination_ip": e.destination_ip,
            "summary": e.description or e.event_type,
            "mitre_technique": technique.id if technique else None,
            "mitre_technique_name": technique.name if technique else None,
            "mitre_tactic": technique.tactic if technique else e.mitre_tactic,
            "severity": e.severity.value if hasattr(e.severity, "value") else e.severity,
        })

    for run in runs:
        for action in (run.action_log or []):
            timeline_entries.append({
                "timestamp": action.get("timestamp"),
                "kind": "response_action",
                "source": "orchestrator",
                "summary": f"[{run.playbook_name}] {action.get('step')}: {action.get('result')}",
                "playbook_run_id": run.id,
                "triggered_by": run.triggered_by,
            })

    timeline_entries.sort(key=lambda x: x["timestamp"] or "")

    kill_chain_span = mitre_attack.tactic_progression_score(incident.mitre_tactics or [])

    return {
        "incident_id": incident.id,
        "title": incident.title,
        "severity": incident.severity.value if hasattr(incident.severity, "value") else incident.severity,
        "status": incident.status.value if hasattr(incident.status, "value") else incident.status,
        "mitre_tactics_observed": incident.mitre_tactics,
        "mitre_techniques_observed": incident.mitre_techniques,
        "kill_chain_span_score": kill_chain_span,
        "first_observed": timeline_entries[0]["timestamp"] if timeline_entries else None,
        "last_observed": timeline_entries[-1]["timestamp"] if timeline_entries else None,
        "entry_count": len(timeline_entries),
        "entries": timeline_entries,
    }
