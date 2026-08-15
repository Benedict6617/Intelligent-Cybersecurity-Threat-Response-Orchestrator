from datetime import datetime, timedelta, timezone
from app.core import correlation_engine
from app.models.event import Event, EventSource, EventSeverity


def _evt(minute_offset, **overrides):
    base_time = datetime(2026, 8, 12, 9, 0, 0, tzinfo=timezone.utc)
    defaults = dict(
        source=EventSource.SIEM, event_type="authentication_failure", severity=EventSeverity.LOW,
        host="DC-SVR-002", occurred_at=base_time + timedelta(minutes=minute_offset),
    )
    defaults.update(overrides)
    return Event(**defaults)


def test_cluster_events_groups_same_host_within_window():
    events = [_evt(0), _evt(3), _evt(6)]
    clusters = correlation_engine.cluster_events(events, window_minutes=15)
    assert len(clusters) == 1
    assert len(clusters[0]) == 3


def test_cluster_events_splits_when_gap_exceeds_window():
    events = [_evt(0), _evt(3), _evt(200)]
    clusters = correlation_engine.cluster_events(events, window_minutes=15)
    assert len(clusters) == 1  # only the first pair clusters; the isolated event is dropped (len==1)
    assert len(clusters[0]) == 2


def test_score_cluster_kill_chain_boosts_confidence():
    events = [
        _evt(0, mitre_tactic="Initial Access", severity=EventSeverity.MEDIUM),
        _evt(5, mitre_tactic="Credential Access", severity=EventSeverity.HIGH),
        _evt(10, mitre_tactic="Impact", severity=EventSeverity.CRITICAL, source=EventSource.EDR),
    ]
    result = correlation_engine.score_cluster(events)
    assert result["confidence"] > 50
    assert result["severity"].value in ("high", "critical")


def test_score_cluster_low_signal_stays_low_confidence():
    events = [_evt(0, severity=EventSeverity.INFO), _evt(2, severity=EventSeverity.INFO)]
    result = correlation_engine.score_cluster(events)
    assert result["confidence"] < 30
