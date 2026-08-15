"""
Generates realistic, internally-consistent sample data for the
Intelligent Cybersecurity Threat Response Orchestrator, including:

  - siem_logs.json          Splunk-style authentication/network events
  - edr_alerts.json         CrowdStrike-style endpoint telemetry
  - firewall_logs.json      Palo Alto-style perimeter traffic/blocks
  - cloud_audit_logs.json   AWS CloudTrail-style API activity
  - threat_intel_feed.json  IOC feed (IPs, domains, hashes)

Two attack narratives are woven through the data for demo realism:
  1. A phishing -> credential theft -> lateral movement -> exfiltration
     chain against user "jmartinez" / host "FIN-WKS-014".
  2. A ransomware precursor: brute force -> discovery -> mass encryption
     against host "DC-SVR-002".
Plus ~70% ordinary benign/noisy background telemetry (scanner traffic,
routine logins, normal cloud API calls) to make correlation meaningful.

Run: python scripts/generate_sample_data.py
"""
import json
import os
import random
from datetime import datetime, timedelta, timezone

random.seed(42)
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "sample_data")
os.makedirs(OUT_DIR, exist_ok=True)

NOW = datetime(2026, 8, 12, 9, 0, 0, tzinfo=timezone.utc)


def ts(offset_minutes):
    return (NOW + timedelta(minutes=offset_minutes)).isoformat()


def write(name, data):
    path = os.path.join(OUT_DIR, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"wrote {len(data)} records -> {path}")


# ---------------------------------------------------------------------------
# SIEM logs (authentication, DNS, general security events)
# ---------------------------------------------------------------------------
siem_logs = []

# Narrative 1: phishing -> creds -> lateral movement -> exfil (jmartinez / FIN-WKS-014)
siem_logs += [
    {"source": "siem", "source_product": "Splunk Enterprise Security", "event_type": "email_phishing",
     "severity": "medium", "host": "FIN-WKS-014", "user": "jmartinez", "source_ip": "203.0.113.44",
     "description": "Inbound email flagged for spoofed sender domain 'accounts-secure-billing.com' impersonating Finance vendor.",
     "occurred_at": ts(0)},
    {"source": "siem", "source_product": "Splunk Enterprise Security", "event_type": "authentication_success_anomalous_location",
     "severity": "high", "host": "FIN-WKS-014", "user": "jmartinez", "source_ip": "185.220.101.47",
     "description": "Successful VPN authentication for jmartinez from IP geolocated to Bucharest, RO; user's typical location is Austin, TX.",
     "occurred_at": ts(6)},
    {"source": "siem", "source_product": "Splunk Enterprise Security", "event_type": "impossible_travel",
     "severity": "high", "host": None, "user": "jmartinez", "source_ip": "185.220.101.47",
     "description": "Impossible travel detected: prior login from Austin, TX 11 minutes before login from Bucharest, RO.",
     "occurred_at": ts(7)},
    {"source": "siem", "source_product": "Splunk Enterprise Security", "event_type": "dns_high_entropy_query",
     "severity": "medium", "host": "FIN-WKS-014", "user": "jmartinez", "source_ip": "10.20.4.14",
     "destination_ip": None,
     "description": "High-entropy DNS query pattern observed to *.n7x2q.duckdns.org, consistent with DNS tunneling.",
     "occurred_at": ts(18)},
]

# Narrative 2: brute force -> discovery -> ransomware precursor (DC-SVR-002)
attacker_ip = "198.51.100.23"
for i in range(9):
    siem_logs.append({
        "source": "siem", "source_product": "Splunk Enterprise Security", "event_type": "authentication_failure",
        "severity": "low", "host": "DC-SVR-002", "user": f"svc_backup{i%3}", "source_ip": attacker_ip,
        "description": f"Failed RDP authentication attempt #{i+1} against service account.",
        "occurred_at": ts(120 + i * 2),
    })
siem_logs.append({
    "source": "siem", "source_product": "Splunk Enterprise Security", "event_type": "authentication_failure_multi_account",
    "severity": "medium", "host": "DC-SVR-002", "user": None, "source_ip": attacker_ip,
    "description": "Password spraying pattern: 9 failed logins across 3 distinct service accounts within 20 minutes.",
    "occurred_at": ts(140),
})

# Background benign noise
benign_users = ["kwilson", "arahman", "tlefevre", "svc_monitoring", "dnguyen", "bpatel"]
benign_hosts = ["MKT-WKS-002", "ENG-WKS-031", "HR-WKS-009", "SALES-LT-018", "OPS-WKS-005"]
for i in range(40):
    siem_logs.append({
        "source": "siem", "source_product": "Splunk Enterprise Security", "event_type": "authentication_success",
        "severity": "info", "host": random.choice(benign_hosts), "user": random.choice(benign_users),
        "source_ip": f"10.20.{random.randint(1,8)}.{random.randint(10,250)}",
        "description": "Routine successful badge-in VPN authentication.",
        "occurred_at": ts(random.randint(-600, 600)),
    })

write("siem_logs.json", siem_logs)

# ---------------------------------------------------------------------------
# EDR alerts (endpoint telemetry)
# ---------------------------------------------------------------------------
edr_alerts = [
    {"source": "edr", "source_product": "CrowdStrike Falcon", "event_type": "edr_powershell_suspicious",
     "severity": "high", "host": "FIN-WKS-014", "user": "jmartinez", "process_name": "powershell.exe",
     "description": "Obfuscated PowerShell execution with -EncodedCommand flag launched from Outlook.exe child process.",
     "occurred_at": ts(20)},
    {"source": "edr", "source_product": "CrowdStrike Falcon", "event_type": "edr_lsass_access",
     "severity": "critical", "host": "FIN-WKS-014", "user": "jmartinez", "process_name": "rundll32.exe",
     "description": "Suspicious handle opened to lsass.exe memory, consistent with credential dumping tooling (Mimikatz-like behavior).",
     "occurred_at": ts(24)},
    {"source": "edr", "source_product": "CrowdStrike Falcon", "event_type": "edr_smb_lateral_movement",
     "severity": "high", "host": "FIN-WKS-014", "user": "jmartinez", "process_name": "svchost.exe",
     "description": "Anomalous SMB admin share (C$) connection from FIN-WKS-014 to FIN-FILESRV-01.",
     "occurred_at": ts(33)},
    {"source": "edr", "source_product": "CrowdStrike Falcon", "event_type": "edr_archive_utility_suspicious",
     "severity": "medium", "host": "FIN-FILESRV-01", "user": "jmartinez", "process_name": "7za.exe",
     "description": "Bulk archive creation of files under \\Finance\\Q3_Reports\\ immediately followed by outbound connection.",
     "occurred_at": ts(40)},
    {"source": "edr", "source_product": "CrowdStrike Falcon", "event_type": "edr_account_enumeration",
     "severity": "medium", "host": "DC-SVR-002", "user": "svc_backup1", "process_name": "net.exe",
     "description": "'net user /domain' and 'net group \"Domain Admins\" /domain' executed by service account (unusual for this principal).",
     "occurred_at": ts(150)},
    {"source": "edr", "source_product": "CrowdStrike Falcon", "event_type": "edr_shadow_copy_deleted",
     "severity": "critical", "host": "DC-SVR-002", "user": "svc_backup1", "process_name": "vssadmin.exe",
     "description": "vssadmin.exe delete shadows /all /quiet executed - shadow copy deletion is a common ransomware precursor.",
     "occurred_at": ts(165)},
    {"source": "edr", "source_product": "CrowdStrike Falcon", "event_type": "edr_mass_file_encryption",
     "severity": "critical", "host": "DC-SVR-002", "user": "svc_backup1", "process_name": "svchost.exe",
     "description": "Mass file rename/encryption detected: 1,240 files renamed with .lockbit3 extension in \\Shares\\Finance in under 90 seconds.",
     "occurred_at": ts(170)},
]

for i in range(15):
    edr_alerts.append({
        "source": "edr", "source_product": "CrowdStrike Falcon", "event_type": "edr_registry_run_key_modified",
        "severity": "info", "host": random.choice(benign_hosts), "user": random.choice(benign_users),
        "process_name": "msiexec.exe",
        "description": "Standard software deployment via SCCM modified a registry run key (approved change window CHG0041932).",
        "occurred_at": ts(random.randint(-400, 400)),
    })

write("edr_alerts.json", edr_alerts)

# ---------------------------------------------------------------------------
# Firewall logs (perimeter/NGFW)
# ---------------------------------------------------------------------------
firewall_logs = [
    {"source": "firewall", "source_product": "Palo Alto NGFW", "event_type": "firewall_c2_beacon",
     "severity": "high", "host": "FIN-WKS-014", "source_ip": "10.20.4.14", "destination_ip": "185.220.101.47",
     "description": "Periodic HTTPS beacon (every 60s +/- 2s jitter) to IP with no reverse DNS, matches threat intel IOC.",
     "occurred_at": ts(28)},
    {"source": "firewall", "source_product": "Palo Alto NGFW", "event_type": "firewall_large_outbound_transfer",
     "severity": "critical", "host": "FIN-FILESRV-01", "source_ip": "10.20.6.22", "destination_ip": "185.220.101.47",
     "description": "Outbound transfer of 1.8 GB over HTTPS to previously-unseen external host within a 4-minute window.",
     "occurred_at": ts(42)},
    {"source": "firewall", "source_product": "Palo Alto NGFW", "event_type": "firewall_rdp_lateral",
     "severity": "medium", "host": "DC-SVR-002", "source_ip": attacker_ip, "destination_ip": "10.20.1.5",
     "description": "RDP (3389/tcp) connection permitted from external-facing DMZ host to domain controller subnet.",
     "occurred_at": ts(118)},
]
for i in range(20):
    firewall_logs.append({
        "source": "firewall", "source_product": "Palo Alto NGFW", "event_type": "firewall_allowed_connection",
        "severity": "info", "host": random.choice(benign_hosts), "source_ip": f"10.20.{random.randint(1,8)}.{random.randint(10,250)}",
        "destination_ip": f"104.18.{random.randint(1,254)}.{random.randint(1,254)}",
        "description": "Routine outbound HTTPS connection to approved SaaS CDN range.",
        "occurred_at": ts(random.randint(-500, 500)),
    })

write("firewall_logs.json", firewall_logs)

# ---------------------------------------------------------------------------
# Cloud audit logs (CloudTrail-style)
# ---------------------------------------------------------------------------
cloud_audit_logs = [
    {"source": "cloud", "source_product": "AWS CloudTrail", "event_type": "cloud_iam_policy_change_suspicious",
     "severity": "high", "user": "jmartinez", "source_ip": "185.220.101.47",
     "description": "IAM policy 'finance-readonly' modified to attach AdministratorAccess to role 'finance-automation-role'.",
     "occurred_at": ts(50)},
    {"source": "cloud", "source_product": "AWS CloudTrail", "event_type": "cloud_storage_bulk_upload",
     "severity": "medium", "user": "jmartinez", "source_ip": "185.220.101.47",
     "description": "47 objects (2.1 GB total) uploaded to newly-created, publicly-writable S3 bucket 'backup-sync-temp-88213'.",
     "occurred_at": ts(55)},
    {"source": "cloud", "source_product": "AWS CloudTrail", "event_type": "cloud_anomalous_compute_spike",
     "severity": "low", "user": "svc_ci_pipeline", "source_ip": "10.20.9.4",
     "description": "EC2 fleet scaled from 4 to 40 instances outside of normal deployment window; consistent with cryptomining or load-testing.",
     "occurred_at": ts(300)},
]
for i in range(12):
    cloud_audit_logs.append({
        "source": "cloud", "source_product": "AWS CloudTrail", "event_type": "cloud_api_call",
        "severity": "info", "user": random.choice(benign_users), "source_ip": f"10.20.{random.randint(1,8)}.{random.randint(10,250)}",
        "description": "Routine read-only S3/EC2 describe API call via approved CI/CD role.",
        "occurred_at": ts(random.randint(-500, 500)),
    })

write("cloud_audit_logs.json", cloud_audit_logs)

# ---------------------------------------------------------------------------
# Threat intel feed (IOCs)
# ---------------------------------------------------------------------------
threat_intel_feed = [
    {"indicator_type": "ip", "value": "185.220.101.47", "confidence": 0.93, "source_feed": "AlienVault OTX",
     "tags": ["tor-exit-node", "c2-infrastructure"], "mitre_techniques": ["T1071.001", "T1041"]},
    {"indicator_type": "ip", "value": "198.51.100.23", "confidence": 0.81, "source_feed": "AlienVault OTX",
     "tags": ["brute-force-source", "known-scanner"], "mitre_techniques": ["T1110"]},
    {"indicator_type": "domain", "value": "accounts-secure-billing.com", "confidence": 0.88, "source_feed": "PhishTank",
     "tags": ["phishing", "typosquat"], "mitre_techniques": ["T1566.001", "T1566.002"]},
    {"indicator_type": "domain", "value": "n7x2q.duckdns.org", "confidence": 0.76, "source_feed": "AlienVault OTX",
     "tags": ["dns-tunneling", "dynamic-dns"], "mitre_techniques": ["T1071.004"]},
    {"indicator_type": "hash_sha256",
     "value": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
     "confidence": 0.95, "source_feed": "VirusTotal", "tags": ["lockbit3", "ransomware"],
     "mitre_techniques": ["T1486", "T1490"]},
    {"indicator_type": "hash_sha256",
     "value": "a94a8fe5ccb19ba61c4c0873d391e987982fbbd3a94a8fe5ccb19ba61c4c087",
     "confidence": 0.70, "source_feed": "MISP", "tags": ["credential-dumping-tool"],
     "mitre_techniques": ["T1003"]},
    {"indicator_type": "url", "value": "https://accounts-secure-billing.com/invoice/verify",
     "confidence": 0.87, "source_feed": "PhishTank", "tags": ["phishing-landing-page"],
     "mitre_techniques": ["T1566.002"]},
]

write("threat_intel_feed.json", threat_intel_feed)

print("\nSample data generation complete.")
print("Attack narratives embedded: phishing->credential theft->lateral movement->exfil (jmartinez/FIN-WKS-014),")
print("brute force->discovery->ransomware precursor (DC-SVR-002).")
