from app.core.playbook_engine import load_playbooks, select_playbook, _severity_at_least
from app.models.incident import Incident, IncidentSeverity


def test_load_playbooks_returns_all_defined_playbooks():
    playbooks = load_playbooks()
    names = {p["name"] for p in playbooks}
    assert {"ransomware_containment", "phishing_response", "brute_force_lockout", "malware_isolation"} <= names


def test_select_playbook_matches_ransomware_techniques():
    incident = Incident(title="t", severity=IncidentSeverity.CRITICAL, mitre_techniques=["T1486", "T1490"])
    playbook = select_playbook(incident)
    assert playbook["name"] == "ransomware_containment"


def test_select_playbook_returns_none_for_unmatched_techniques():
    incident = Incident(title="t", severity=IncidentSeverity.LOW, mitre_techniques=["T9999"])
    assert select_playbook(incident) is None


def test_severity_at_least_ordering():
    assert _severity_at_least("high", "medium") is True
    assert _severity_at_least("low", "high") is False
