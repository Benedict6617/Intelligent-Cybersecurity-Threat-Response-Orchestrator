from datetime import datetime, timedelta, timezone
from app.core import escalation_matrix
from app.models.incident import Incident, IncidentSeverity, IncidentStatus


def test_ransomware_technique_forces_critical_escalation():
    incident = Incident(title="test", severity=IncidentSeverity.MEDIUM, mitre_techniques=["T1486"])
    tier = escalation_matrix.resolve_tier(incident)
    assert tier.level == 4


def test_low_severity_maps_to_l1():
    incident = Incident(title="test", severity=IncidentSeverity.LOW, mitre_techniques=[])
    tier = escalation_matrix.resolve_tier(incident)
    assert tier.level == 1


def test_sla_breach_detection():
    incident = Incident(
        title="test", severity=IncidentSeverity.HIGH, status=IncidentStatus.TRIAGING,
        sla_due_at=datetime.now(timezone.utc) - timedelta(minutes=5),
    )
    assert escalation_matrix.is_sla_breached(incident) is True


def test_no_breach_when_within_sla():
    incident = Incident(
        title="test", severity=IncidentSeverity.HIGH, status=IncidentStatus.TRIAGING,
        sla_due_at=datetime.now(timezone.utc) + timedelta(minutes=30),
    )
    assert escalation_matrix.is_sla_breached(incident) is False
