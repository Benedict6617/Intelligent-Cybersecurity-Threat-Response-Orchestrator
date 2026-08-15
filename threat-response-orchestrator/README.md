# Intelligent Cybersecurity Threat Response Orchestrator

A SOAR (Security Orchestration, Automation and Response) platform built for
small and mid-size security teams that need enterprise-grade incident
response capability without an enterprise-grade budget or headcount.

It ingests telemetry from SIEM, EDR, firewall, and cloud sources; correlates
related events into incidents using the MITRE ATT&CK framework; suppresses
false positives; runs automated containment playbooks; coordinates ticket
creation in your ITSM system; manages incident escalation with SLA
tracking; reconstructs forensic timelines; and generates SOC 2 / ISO 27001
audit evidence.

> This is an original reference implementation built for this brief. It
> does not copy or vendor code from any existing open-source SOAR project.

## Why this exists

Commercial SOAR platforms (Splunk SOAR, Palo Alto XSOAR, etc.) are built
for enterprise SOCs with dedicated automation engineers and six-figure
licensing budgets. A small business with one or two security analysts
still faces the same alert fatigue and containment-speed problem, just at
smaller scale. This project is a lean, self-hostable, source-available
alternative: a single FastAPI service, a SQL database, and declarative
YAML playbooks — no proprietary automation DSL, no vendor lock-in.

## Core capabilities

| Capability | Where it lives |
|---|---|
| Multi-source event ingestion (SIEM/EDR/firewall/cloud/identity) | `app/api/routes/ingestion.py`, `app/connectors/` |
| MITRE ATT&CK-based correlation engine | `app/core/correlation_engine.py`, `app/core/mitre_attack.py` |
| False positive suppression | `app/core/false_positive_filter.py` |
| ML-based anomaly detection (IsolationForest) | `app/core/anomaly_detection.py` |
| Automated containment playbooks (YAML-defined) | `app/core/playbook_engine.py`, `app/playbooks/` |
| ITSM ticket coordination | `app/core/itsm_connector.py` |
| Incident escalation matrix + SLA tracking | `app/core/escalation_matrix.py` |
| Forensic timeline reconstruction | `app/core/forensic_timeline.py` |
| Threat intelligence feed ingestion & IOC matching | `app/core/threat_intel_feed.py` |
| SOC 2 / ISO 27001 compliance reporting | `app/core/compliance_reporter.py` |
| Analyst dashboard (SOC console UI) | `dashboard/` |

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

cp .env.example .env
python scripts/generate_sample_data.py     # generates realistic sample logs
uvicorn app.main:app --reload
```

Open:
- **API docs:** http://localhost:8000/docs
- **Analyst dashboard:** http://localhost:8000/dashboard

Then, in a second terminal, replay the bundled attack scenarios through the
live API to see correlation, escalation, and playbook selection happen
end-to-end:

```bash
python scripts/simulate_attack.py
```

Or seed the database directly without running the server:

```bash
python scripts/seed_database.py
```

Prefer Docker?

```bash
cp .env.example .env
docker compose up --build
```

## Sample data included

`sample_data/` ships realistic, internally-consistent log data across all
four source types, built around two attack narratives so correlation has
something meaningful to find:

1. **Phishing → credential theft → lateral movement → exfiltration**
   against user `jmartinez` on host `FIN-WKS-014`, spanning SIEM,
   EDR, firewall, and cloud (CloudTrail-style) logs.
2. **Password spraying → discovery → ransomware precursor** against
   `DC-SVR-002`, including shadow-copy deletion and mass file encryption.

Roughly 70% of the bundled data is ordinary benign background telemetry
(routine logins, scanner traffic, normal cloud API calls) so the
correlation and false-positive-suppression logic have real signal to
separate from noise — not just a curated "all events are the attack" demo.

Regenerate or extend it any time with `python scripts/generate_sample_data.py`.

## Running the tests

```bash
pytest
```

Covers the correlation engine, false-positive filter, escalation matrix,
and playbook selection logic.

## Project structure

```
app/
  main.py                 FastAPI entrypoint
  config.py                Settings (env-driven)
  database.py               SQLAlchemy engine/session
  models/                    ORM models (events, incidents, playbooks, tickets, IOCs, audit log)
  schemas/                    Pydantic request/response schemas
  api/routes/                  HTTP routers (ingestion, incidents, playbooks, threat-intel, compliance, dashboard)
  core/                          Detection & response logic (correlation, ML, escalation, playbooks, ITSM, compliance, forensic timeline)
  connectors/                     SIEM/EDR/firewall/cloud integration adapters
  playbooks/                       Declarative YAML response playbooks
dashboard/                 Static analyst SOC console UI
sample_data/               Realistic bundled log data + threat intel feed
scripts/                   Sample data generation, seeding, attack simulation
tests/                      Pytest suite
docs/                        Architecture, API reference, deployment guide, compliance mapping
```

See `docs/ARCHITECTURE.md` for a full data-flow walkthrough, `docs/API.md`
for the endpoint reference, `docs/DEPLOYMENT.md` for production
hardening notes, and `docs/COMPLIANCE_MAPPING.md` for how platform
activity maps to SOC 2 / ISO 27001 control themes.

## Production readiness notes

This ships as a working reference implementation, not a turnkey product.
Before running it against real infrastructure:

- Swap SQLite for PostgreSQL (`DATABASE_URL` in `.env`).
- Put the API behind your SSO/IdP — no auth layer is bundled by default.
- Replace the simulated connector calls in `app/connectors/*.py` with real
  API calls once you have EDR/firewall/identity credentials, and validate
  playbooks in dry-run mode in a staging environment first.
- Review `docs/DEPLOYMENT.md` for the full production checklist.

## License

MIT — see `LICENSE`.
