"""
Compliance Reporting (SOC 2 / ISO 27001)
--------------------------------------------
Generates audit-ready evidence summaries mapping platform activity to
common trust services criteria / control domains. This is not a
substitute for a qualified auditor's assessment, but it gives a small
security team a structured, exportable evidence package instead of
manually screenshotting dashboards before an audit.

Mappings below reference:
- SOC 2 Trust Services Criteria (Security / CC-series, AICPA)
- ISO/IEC 27001:2022 Annex A control themes

These are the publicly published control *names*, used here only to
label which platform activity satisfies which control area - no
proprietary ISO/AICPA text is reproduced.
"""
from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy.orm import Session

from app.models.incident import Incident
from app.models.audit_log import AuditLog
from app.models.playbook import PlaybookRun

CONTROL_MAPPING = [
    {
        "control_id": "CC7.2 / A.5.24",
        "framework": ["SOC2", "ISO27001"],
        "name": "Security Incident Detection & Response",
        "description": "The organization detects and responds to security incidents through defined processes.",
        "evidence_source": "incidents",
    },
    {
        "control_id": "CC7.3 / A.5.26",
        "framework": ["SOC2", "ISO27001"],
        "name": "Incident Response Plan Execution",
        "description": "Response to identified security incidents follows a documented, repeatable playbook.",
        "evidence_source": "playbook_runs",
    },
    {
        "control_id": "CC7.4 / A.5.27",
        "framework": ["SOC2", "ISO27001"],
        "name": "Post-Incident Learning",
        "description": "Incidents are reviewed and lessons learned are captured (forensic timeline + closure notes).",
        "evidence_source": "closed_incidents",
    },
    {
        "control_id": "CC6.1 / A.8.16",
        "framework": ["SOC2", "ISO27001"],
        "name": "Monitoring Activities",
        "description": "Logs from network and system components are collected and monitored for security events.",
        "evidence_source": "audit_logs",
    },
    {
        "control_id": "CC9.2 / A.5.19",
        "framework": ["SOC2", "ISO27001"],
        "name": "Third-Party / Ticketing Coordination",
        "description": "Security incidents are tracked to resolution via the IT service management system.",
        "evidence_source": "tickets",
    },
]


def generate_report(db: Session, start: datetime, end: datetime, framework: str = "SOC2") -> dict:
    incidents = db.query(Incident).filter(Incident.created_at.between(start, end)).all()
    closed = [i for i in incidents if i.status.value == "closed"]
    runs = db.query(PlaybookRun).filter(PlaybookRun.started_at.between(start, end)).all()
    audit_events = db.query(AuditLog).filter(AuditLog.timestamp.between(start, end)).count()

    sla_met = [i for i in incidents if i.contained_at and i.sla_due_at and i.contained_at <= i.sla_due_at]
    sla_compliance_pct = round((len(sla_met) / len(incidents) * 100), 1) if incidents else 100.0

    controls_evidence = []
    for control in CONTROL_MAPPING:
        if framework not in control["framework"]:
            continue
        if control["evidence_source"] == "incidents":
            evidence_count = len(incidents)
        elif control["evidence_source"] == "playbook_runs":
            evidence_count = len(runs)
        elif control["evidence_source"] == "closed_incidents":
            evidence_count = len(closed)
        elif control["evidence_source"] == "audit_logs":
            evidence_count = audit_events
        elif control["evidence_source"] == "tickets":
            evidence_count = len([i for i in incidents if i.ticket_id])
        else:
            evidence_count = 0

        controls_evidence.append({
            **control,
            "evidence_count": evidence_count,
            "status": "satisfied" if evidence_count > 0 else "no_evidence_in_period",
        })

    return {
        "framework": framework,
        "report_period": {"start": start.isoformat(), "end": end.isoformat()},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_incidents": len(incidents),
            "closed_incidents": len(closed),
            "critical_incidents": len([i for i in incidents if i.severity.value == "critical"]),
            "automated_playbook_runs": len(runs),
            "sla_compliance_pct": sla_compliance_pct,
            "audit_log_entries": audit_events,
        },
        "controls": controls_evidence,
    }
