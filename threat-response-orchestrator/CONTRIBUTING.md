# Contributing

Thanks for considering a contribution to the Intelligent Cybersecurity
Threat Response Orchestrator.

## Development setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
python scripts/generate_sample_data.py
pytest
```

## Guidelines

- Keep detection/response logic explainable — prefer documented heuristics
  over opaque scoring wherever practical; this is a SOC tool and analysts
  need to be able to answer "why did this fire" during an audit.
- Add or update tests under `tests/` for any change to `app/core/*`.
- New connectors go in `app/connectors/`; keep the safe-simulation default
  (no real destructive calls without explicit configuration).
- New playbooks are just YAML — see `app/playbooks/` for the schema. No
  code change is required to add one unless it needs a new action type.
- Run `pytest` before opening a pull request.

## Reporting security issues

Please see `SECURITY.md` rather than opening a public issue.
