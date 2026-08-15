from datetime import datetime, timezone
from app.core import false_positive_filter
from app.models.event import Event, EventSource, EventSeverity


def _make_event(**overrides):
    defaults = dict(
        source=EventSource.SIEM, event_type="authentication_success", severity=EventSeverity.INFO,
        host="WKS-001", user="jdoe", source_ip="10.0.0.5", occurred_at=datetime.now(timezone.utc),
    )
    defaults.update(overrides)
    return Event(**defaults)


def test_allowlisted_scanner_host_is_suppressed():
    event = _make_event(host="vuln-scanner-01")
    result = false_positive_filter.evaluate(event)
    assert result.suppressed is True
    assert "allowlist" in result.reason


def test_allowlisted_scanner_ip_is_suppressed():
    event = _make_event(source_ip="10.10.5.50")
    result = false_positive_filter.evaluate(event)
    assert result.suppressed is True


def test_high_severity_unknown_host_not_suppressed():
    event = _make_event(host="FIN-WKS-014", severity=EventSeverity.CRITICAL, anomaly_score=0.9)
    result = false_positive_filter.evaluate(event, historical_fp_rate=0.1)
    assert result.suppressed is False


def test_high_historical_fp_rate_with_low_anomaly_suppressed():
    event = _make_event(host="MKT-WKS-002", anomaly_score=0.05)
    result = false_positive_filter.evaluate(event, historical_fp_rate=0.9)
    assert result.suppressed is True
