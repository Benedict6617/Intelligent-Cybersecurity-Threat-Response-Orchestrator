# Deployment Guide

## Local evaluation (no Docker)

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt

cp .env.example .env
python scripts/generate_sample_data.py   # (re)generate sample_data/*.json

uvicorn app.main:app --reload
```

Then visit:
- `http://localhost:8000/docs` — interactive API docs
- `http://localhost:8000/dashboard` — analyst dashboard

Load the bundled attack scenarios into the running API:

```bash
python scripts/simulate_attack.py
```

## Docker

```bash
cp .env.example .env
docker compose up --build
```

The API is available on `http://localhost:8000`. SQLite data persists in
`./data` on the host via the mounted volume.

## Production recommendations (small business scale)

1. **Database**: switch `DATABASE_URL` to a managed PostgreSQL instance
   (e.g. RDS, Cloud SQL, or a reputable managed Postgres provider). SQLite
   is fine for evaluation but does not handle concurrent writes well
   under real SIEM/EDR ingestion volume.
2. **Secrets**: set a strong, unique `SECRET_KEY`, and store real
   `ITSM_API_TOKEN`, `SLACK_WEBHOOK_URL`, and SMTP credentials in your
   platform's secret manager, not in `.env` committed to source control.
3. **TLS & reverse proxy**: run behind Caddy, Nginx, or your cloud
   provider's load balancer with TLS termination. Do not expose port 8000
   directly to the internet.
4. **Process manager**: run with multiple Uvicorn/Gunicorn workers, e.g.
   `gunicorn app.main:app -k uvicorn.workers.UvicornWorker -w 4`.
5. **Migrations**: this reference implementation calls
   `Base.metadata.create_all()` on startup for simplicity. For an evolving
   production schema, introduce Alembic migrations instead.
6. **Backups**: schedule regular database backups; incident and audit log
   data is the primary evidence trail for SOC2/ISO27001 audits and must
   be retained per your organization's data retention policy.
7. **Authentication**: this reference implementation does not ship an
   auth layer (the `SECRET_KEY`/JWT settings are scaffolding for you to
   wire up). Put the API and dashboard behind your SSO/IdP (e.g. via the
   reverse proxy or an auth middleware) before exposing it beyond a
   trusted internal network.
8. **Connector credentials**: replace the simulated connector functions
   in `app/connectors/*.py` with real API calls once you have credentials
   for your EDR, firewall, and identity platforms. Keep dry-run mode on
   until you've validated playbook behavior in a staging environment.
9. **Scheduled jobs**: wire `apscheduler` (already a dependency) to poll
   SIEM/threat-intel connectors on an interval and call `/ingest/batch`
   and `/threat-intel/sync` automatically, instead of relying on manual
   script runs.

## Environment variables

See `.env.example` for the full list with inline documentation.
