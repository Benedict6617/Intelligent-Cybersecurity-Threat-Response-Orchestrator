"""
ML-Based Anomaly Detection
----------------------------
Uses an IsolationForest (scikit-learn) trained on lightweight behavioral
features derived from normalized events to flag statistically unusual
activity that rule-based detections might miss (e.g. an account
authenticating at an unusual hour from a rarely-seen source, or a host
generating an abnormal volume of events).

This is deliberately a simple, explainable model appropriate for a small
security team to operate without a dedicated data science function. It
is trained per-run on the current event window; for production scale,
persist the fitted model (joblib) and retrain on a schedule instead of
per-request.
"""
from __future__ import annotations

from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest

from app.config import get_settings
from app.models.event import Event

settings = get_settings()

FEATURE_COLUMNS = [
    "hour_of_day",
    "severity_rank",
    "events_from_source_ip_last_24h",
    "events_from_user_last_24h",
    "is_off_hours",
    "distinct_hosts_touched_by_user",
]

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class AnomalyResult:
    event_id: str
    anomaly_score: float  # 0 (normal) .. 1 (highly anomalous)
    is_anomaly: bool


def _build_features(events: list[Event]) -> pd.DataFrame:
    rows = []
    user_counts: dict[str, int] = {}
    ip_counts: dict[str, int] = {}
    user_hosts: dict[str, set] = {}

    for e in events:
        if e.user:
            user_counts[e.user] = user_counts.get(e.user, 0) + 1
            user_hosts.setdefault(e.user, set())
            if e.host:
                user_hosts[e.user].add(e.host)
        if e.source_ip:
            ip_counts[e.source_ip] = ip_counts.get(e.source_ip, 0) + 1

    for e in events:
        hour = e.occurred_at.hour
        rows.append({
            "event_id": e.id,
            "hour_of_day": hour,
            "severity_rank": SEVERITY_RANK.get(e.severity.value if hasattr(e.severity, "value") else e.severity, 0),
            "events_from_source_ip_last_24h": ip_counts.get(e.source_ip, 1) if e.source_ip else 0,
            "events_from_user_last_24h": user_counts.get(e.user, 1) if e.user else 0,
            "is_off_hours": 1 if (hour < 6 or hour > 21) else 0,
            "distinct_hosts_touched_by_user": len(user_hosts.get(e.user, set())) if e.user else 0,
        })
    return pd.DataFrame(rows)


def score_events(events: list[Event]) -> list[AnomalyResult]:
    """
    Fit an IsolationForest over the feature matrix of the provided event
    batch and return per-event anomaly scores. Requires a minimum batch
    size to produce meaningful scores; smaller batches fall back to a
    neutral score.
    """
    if len(events) < 8:
        return [AnomalyResult(e.id, 0.1, False) for e in events]

    df = _build_features(events)
    X = df[FEATURE_COLUMNS].values

    model = IsolationForest(
        n_estimators=200,
        contamination=settings.ANOMALY_CONTAMINATION,
        random_state=42,
    )
    model.fit(X)

    raw_scores = model.decision_function(X)  # higher = more normal
    predictions = model.predict(X)  # -1 = anomaly, 1 = normal

    # Normalize raw_scores (typically in [-0.5, 0.5]) to a 0..1 "anomalousness" score
    normalized = 1 - (raw_scores - raw_scores.min()) / (raw_scores.max() - raw_scores.min() + 1e-9)

    results = []
    for i, e in enumerate(events):
        results.append(AnomalyResult(
            event_id=e.id,
            anomaly_score=round(float(normalized[i]), 4),
            is_anomaly=bool(predictions[i] == -1),
        ))
    return results
