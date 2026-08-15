"""
Incident Escalation Matrix
----------------------------
Defines SLA response targets and escalation paths by incident severity,
and the logic for auto-escalating an incident when it breaches SLA or
when specific high-impact MITRE techniques are observed (e.g. ransomware
indicators escalate straight to the IR lead + CISO regardless of SLA).

Configure `ESCALATION_MATRIX` to match your organization's real on-call
structure (PagerDuty/Opsgenie schedules, org chart, etc).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from app.models.incident import Incident, IncidentSeverity

# Techniques that, if observed, force immediate escalation to level 4
# regardless of the computed confidence/severity (crown-jewel scenarios).
CRITICAL_AUTO_ESCALATE_TECHNIQUES = {
    "T1486",  # Data Encrypted for Impact (ransomware)
    "T1490",  # Inhibit System Recovery
    "T1531",  # Account Access Removal
}


@dataclass
class EscalationTier:
    level: int
    name: str
    notify: list[str]           # roles/aliases to notify
    sla_minutes: int            # time to first response
    requires_ticket: bool = True


ESCALATION_MATRIX: dict[IncidentSeverity, EscalationTier] = {
    IncidentSeverity.LOW: EscalationTier(
        level=1, name="SOC Analyst (L1)", notify=["soc-l1@example-corp.local"],
        sla_minutes=480, requires_ticket=True,
    ),
    IncidentSeverity.MEDIUM: EscalationTier(
        level=2, name="SOC Analyst (L2)", notify=["soc-l2@example-corp.local"],
        sla_minutes=120, requires_ticket=True,
    ),
    IncidentSeverity.HIGH: EscalationTier(
        level=3, name="Incident Response Lead", notify=["ir-lead@example-corp.local", "soc-l2@example-corp.local"],
        sla_minutes=30, requires_ticket=True,
    ),
    IncidentSeverity.CRITICAL: EscalationTier(
        level=4, name="CISO / Executive Bridge", notify=["ciso@example-corp.local", "ir-lead@example-corp.local", "on-call-exec@example-corp.local"],
        sla_minutes=15, requires_ticket=True,
    ),
}


def resolve_tier(incident: Incident) -> EscalationTier:
    if any(t in CRITICAL_AUTO_ESCALATE_TECHNIQUES for t in (incident.mitre_techniques or [])):
        return ESCALATION_MATRIX[IncidentSeverity.CRITICAL]
    return ESCALATION_MATRIX[incident.severity]


def apply_escalation(incident: Incident) -> Incident:
    tier = resolve_tier(incident)
    incident.escalation_level = tier.level
    incident.sla_due_at = datetime.now(timezone.utc) + timedelta(minutes=tier.sla_minutes)
    return incident


def is_sla_breached(incident: Incident) -> bool:
    if incident.sla_due_at is None:
        return False
    if incident.status.value in ("closed", "false_positive", "contained"):
        return False
    return datetime.now(timezone.utc) > incident.sla_due_at.replace(tzinfo=timezone.utc)


def next_escalation_on_breach(incident: Incident) -> EscalationTier | None:
    """If SLA is breached, return the next tier up (max level 4)."""
    if not is_sla_breached(incident):
        return None
    current = resolve_tier(incident)
    next_level = min(current.level + 1, 4)
    for tier in ESCALATION_MATRIX.values():
        if tier.level == next_level:
            return tier
    return None
