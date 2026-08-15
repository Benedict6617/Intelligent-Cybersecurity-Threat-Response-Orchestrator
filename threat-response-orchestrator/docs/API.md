# API Reference

Base URL: `http://localhost:8000/api/v1`
Interactive docs (Swagger UI): `http://localhost:8000/docs`

All endpoints return JSON. This is a summary; the interactive docs are the
source of truth for request/response schemas.

## Ingestion

| Method | Path | Description |
|---|---|---|
| POST | `/ingest/event` | Ingest a single normalized security event. |
| POST | `/ingest/batch` | Bulk-ingest events, then run anomaly scoring + correlation + auto-ticketing for any new incidents. Used by `scripts/simulate_attack.py`. |

## Incidents

| Method | Path | Description |
|---|---|---|
| GET | `/incidents` | List incidents. Filter with `?status=` and `?severity=`. |
| GET | `/incidents/{id}` | Get a single incident. |
| GET | `/incidents/{id}/timeline` | Forensic timeline: events + response actions, chronologically merged and MITRE-mapped. |
| GET | `/incidents/{id}/escalation` | Current escalation tier, SLA due date, and whether SLA has been breached. |
| PATCH | `/incidents/{id}/status` | Update incident status (`new`, `triaging`, `contained`, `eradicating`, `recovering`, `closed`, `false_positive`). |

## Playbooks

| Method | Path | Description |
|---|---|---|
| GET | `/playbooks` | List all defined playbooks and their triggers. |
| POST | `/playbooks/incidents/{incident_id}/execute` | Execute a playbook against an incident. Auto-selects the best-matching playbook if `playbook_name` is omitted. `dry_run: true` (default) simulates every step without calling real connectors. |
| GET | `/playbooks/runs/{run_id}` | Get a playbook run's status and full action log. |

## Threat intelligence

| Method | Path | Description |
|---|---|---|
| POST | `/threat-intel/sync` | Pull the configured feed and upsert indicators. |
| GET | `/threat-intel/indicators` | List stored IOCs. Filter with `?indicator_type=`. |
| GET | `/threat-intel/indicators/lookup?value=` | Check whether a value (IP/domain/hash/URL) matches a known IOC. |

## Compliance

| Method | Path | Description |
|---|---|---|
| GET | `/compliance/report?framework=SOC2&days=90` | Generate an audit evidence summary for the given framework (`SOC2` or `ISO27001`) and lookback window. |

## Dashboard

| Method | Path | Description |
|---|---|---|
| GET | `/dashboard/summary` | Aggregate counters used by the analyst dashboard (open incidents, events/24h, top ATT&CK techniques, etc). |

## Example: ingest a single event

```bash
curl -X POST http://localhost:8000/api/v1/ingest/event \
  -H "Content-Type: application/json" \
  -d '{
    "source": "edr",
    "source_product": "CrowdStrike Falcon",
    "event_type": "edr_mass_file_encryption",
    "severity": "critical",
    "host": "DC-SVR-002",
    "user": "svc_backup1",
    "process_name": "svchost.exe",
    "description": "Mass file rename detected with .lockbit3 extension",
    "occurred_at": "2026-08-12T09:02:50Z"
  }'
```

## Example: execute a playbook (dry run)

```bash
curl -X POST http://localhost:8000/api/v1/playbooks/incidents/{incident_id}/execute \
  -H "Content-Type: application/json" \
  -d '{"dry_run": true, "triggered_by": "analyst.jsmith"}'
```
