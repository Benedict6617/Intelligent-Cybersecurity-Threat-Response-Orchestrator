"""
SIEM Connector (reference implementation)
---------------------------------------------
Adapter for pulling normalized alerts from a SIEM (e.g. Splunk ES,
Microsoft Sentinel, Elastic Security). In production this polls the
SIEM's search/alerts API on a schedule (see scripts and
apscheduler wiring in app/main.py) and posts normalized events to the
ingestion API. This reference implementation reads from the bundled
sample_data/siem_logs.json for local evaluation and demos.
"""
import json
import os

SAMPLE_PATH = os.path.join(os.path.dirname(__file__), "..", "..", "sample_data", "siem_logs.json")


def fetch_recent_alerts() -> list[dict]:
    if not os.path.exists(SAMPLE_PATH):
        return []
    with open(SAMPLE_PATH, "r", encoding="utf-8") as f:
        return json.load(f)
