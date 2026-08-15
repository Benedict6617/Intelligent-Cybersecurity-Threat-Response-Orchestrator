"""
Replays the bundled sample_data/*.json logs through the running
Orchestrator API as a batch ingestion call, so you can see correlation,
false-positive suppression, anomaly scoring, playbook selection, and
ticket creation happen end-to-end against realistic data.

Usage:
    1. Start the API:   uvicorn app.main:app --reload
    2. In another shell: python scripts/simulate_attack.py

Requires `httpx` (already in requirements.txt).
"""
import json
import os
import sys

import httpx

API_BASE = os.environ.get("ORCHESTRATOR_API_BASE", "http://localhost:8000/api/v1")
SAMPLE_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_data")

SOURCE_FILES = [
    "siem_logs.json",
    "edr_alerts.json",
    "firewall_logs.json",
    "cloud_audit_logs.json",
]


def load_all_events() -> list[dict]:
    events = []
    for filename in SOURCE_FILES:
        path = os.path.join(SAMPLE_DIR, filename)
        if not os.path.exists(path):
            print(f"  (skipping missing {filename} - run scripts/generate_sample_data.py first)")
            continue
        with open(path, "r", encoding="utf-8") as f:
            batch = json.load(f)
            events.extend(batch)
    return events


def main():
    print(f"Loading sample events from {SAMPLE_DIR} ...")
    events = load_all_events()
    print(f"Loaded {len(events)} events. Posting to {API_BASE}/ingest/batch ...")

    try:
        resp = httpx.post(f"{API_BASE}/ingest/batch", json=events, timeout=60)
        resp.raise_for_status()
    except httpx.ConnectError:
        print("\nERROR: Could not reach the API. Is it running? Start it with:")
        print("    uvicorn app.main:app --reload\n")
        sys.exit(1)

    result = resp.json()
    print(f"\nIngested: {result['events_ingested']} events")
    print(f"Incidents created: {len(result['incidents_created'])}")
    for incident_id in result["incidents_created"]:
        inc = httpx.get(f"{API_BASE}/incidents/{incident_id}", timeout=30).json()
        print(f"  - [{inc['severity'].upper()}] {inc['id']}: {inc['title']} "
              f"(confidence={inc['confidence_score']}, techniques={inc['mitre_techniques']})")

    print("\nDone. Explore results:")
    print(f"  GET {API_BASE}/dashboard/summary")
    print(f"  GET {API_BASE}/incidents")
    print("  Or open the analyst dashboard at http://localhost:8000/dashboard")


if __name__ == "__main__":
    main()
