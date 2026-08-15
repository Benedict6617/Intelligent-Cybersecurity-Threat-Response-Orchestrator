"""
Reference script for syncing the local MITRE ATT&CK technique table
(app/core/mitre_attack.py) from the official STIX data source.

This ships as a documented stub rather than a live network call so the
project has no hard runtime dependency on an external service. To wire
up a real sync:

    1. pip install stix2 requests
    2. Download the Enterprise ATT&CK STIX bundle from:
       https://github.com/mitre-attack/attack-stix-data
    3. Parse `attack-pattern` objects into Technique(id, name, tactic,
       description) entries and regenerate the TECHNIQUES dict in
       app/core/mitre_attack.py.

Run on a schedule (e.g. monthly) via cron or your orchestration platform
of choice to keep pace with new ATT&CK releases.
"""

STIX_BUNDLE_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"


def main():
    print("This is a reference stub. To sync live ATT&CK data:")
    print(f"  1. Fetch: {STIX_BUNDLE_URL}")
    print("  2. Parse `attack-pattern` STIX objects into Technique entries.")
    print("  3. Regenerate app/core/mitre_attack.py::TECHNIQUES.")
    print("See this file's module docstring for details.")


if __name__ == "__main__":
    main()
