"""
False Positive Suppression
---------------------------
Combines three signals to decide whether an event/incident is likely
noise before it ever reaches an analyst queue or triggers automation:

1. Allowlist rules (known-good hosts/IPs/processes, e.g. vuln scanners)
2. Historical suppression feedback (analysts marking prior similar
   events as false positives - a simple frequency-based Bayesian prior)
3. Anomaly score from the ML model (very low anomaly score + no MITRE
   technique match = likely benign)

This keeps suppression logic transparent and tunable, which matters for
audit purposes: every suppression decision is logged with its reason.
"""
from __future__ import annotations

from dataclasses import dataclass
from sqlalchemy.orm import Session

from app.config import get_settings
from app.models.event import Event

settings = get_settings()

# Example allowlist - in production this would be a managed table/UI.
KNOWN_GOOD_HOSTS = {"vuln-scanner-01", "nessus-scanner", "backup-server-01"}
KNOWN_GOOD_IPS = {"10.10.5.50", "10.10.5.51"}  # internal vuln scanning subnet
BENIGN_PROCESS_PATTERNS = {"backup_agent.exe", "crowdstrike_healthcheck.exe"}


@dataclass
class SuppressionResult:
    suppressed: bool
    reason: str
    confidence: float  # confidence that this IS a false positive, 0-1


def evaluate(event: Event, historical_fp_rate: float | None = None) -> SuppressionResult:
    if event.host in KNOWN_GOOD_HOSTS:
        return SuppressionResult(True, f"Host '{event.host}' is on the scanner/allowlist.", 0.95)

    if event.source_ip in KNOWN_GOOD_IPS:
        return SuppressionResult(True, f"Source IP '{event.source_ip}' is an allowlisted scanning subnet.", 0.9)

    if event.process_name in BENIGN_PROCESS_PATTERNS:
        return SuppressionResult(True, f"Process '{event.process_name}' matches known-benign pattern.", 0.85)

    fp_rate = historical_fp_rate if historical_fp_rate is not None else 0.0
    anomaly_low = event.anomaly_score is not None and event.anomaly_score < 0.15
    no_technique = event.mitre_technique_id is None

    if fp_rate > 0.8 and anomaly_low and no_technique:
        return SuppressionResult(
            True,
            f"Event type '{event.event_type}' has a {fp_rate:.0%} historical false-positive "
            f"rate for this asset and no ATT&CK technique or anomaly signal was matched.",
            min(0.5 + fp_rate / 2, 0.97),
        )

    if fp_rate > 0.8 and anomaly_low:
        return SuppressionResult(
            True,
            f"Event type '{event.event_type}' has a {fp_rate:.0%} historical false-positive rate "
            f"and anomaly score is low ({event.anomaly_score:.2f}).",
            0.6,
        )

    return SuppressionResult(False, "No suppression rule matched.", 0.0)


def compute_historical_fp_rate(db: Session, event_type: str, host: str | None) -> float:
    """
    Frequency-based prior: of past events of this type on this host,
    what fraction were confirmed false positives by an analyst?
    """
    q = db.query(Event).filter(Event.event_type == event_type)
    if host:
        q = q.filter(Event.host == host)
    total = q.count()
    if total == 0:
        return 0.0
    fp = q.filter(Event.is_false_positive == "true").count()
    return fp / total
