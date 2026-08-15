"""
MITRE ATT&CK (Enterprise) reference data.

This module ships a curated subset of publicly documented ATT&CK tactics
and techniques (framework version 15) sufficient to demonstrate realistic
correlation logic for a small/mid-size SOC. The technique IDs and names
are drawn from the public MITRE ATT&CK knowledge base (attack.mitre.org);
no proprietary or copyrighted source code is used here, only the public
taxonomy of tactic/technique identifiers.

In production, replace `TECHNIQUES` with a synced copy of the official
STIX bundle (see https://github.com/mitre-attack/attack-stix-data) and
refresh it on a schedule via `scripts/sync_mitre_attack.py`.
"""
from dataclasses import dataclass, field


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactic: str
    description: str
    related_event_types: tuple = field(default_factory=tuple)


# Kill-chain ordered tactics (Enterprise ATT&CK)
TACTIC_ORDER = [
    "Reconnaissance",
    "Resource Development",
    "Initial Access",
    "Execution",
    "Persistence",
    "Privilege Escalation",
    "Defense Evasion",
    "Credential Access",
    "Discovery",
    "Lateral Movement",
    "Collection",
    "Command and Control",
    "Exfiltration",
    "Impact",
]

TECHNIQUES: dict[str, Technique] = {
    t.id: t for t in [
        Technique("T1566.001", "Phishing: Spearphishing Attachment", "Initial Access",
                   "Adversary sends a malicious attachment to gain initial access.",
                   ("email_malicious_attachment", "email_phishing")),
        Technique("T1566.002", "Phishing: Spearphishing Link", "Initial Access",
                   "Adversary sends a malicious link to gain initial access.",
                   ("email_phishing", "web_malicious_url_click")),
        Technique("T1190", "Exploit Public-Facing Application", "Initial Access",
                   "Adversary exploits a weakness in an internet-facing system.",
                   ("waf_exploit_attempt", "ids_exploit_signature")),
        Technique("T1078", "Valid Accounts", "Initial Access",
                   "Adversary uses legitimate credentials to access a system.",
                   ("authentication_success_anomalous_location", "impossible_travel")),
        Technique("T1059.001", "Command and Scripting Interpreter: PowerShell", "Execution",
                   "Adversary abuses PowerShell for execution.",
                   ("edr_powershell_suspicious", "process_creation_powershell")),
        Technique("T1059.003", "Command and Scripting Interpreter: Windows Command Shell", "Execution",
                   "Adversary abuses cmd.exe for execution.",
                   ("edr_cmd_suspicious",)),
        Technique("T1053.005", "Scheduled Task/Job: Scheduled Task", "Persistence",
                   "Adversary creates a scheduled task for persistence.",
                   ("edr_scheduled_task_created",)),
        Technique("T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys", "Persistence",
                   "Adversary modifies registry run keys for persistence.",
                   ("edr_registry_run_key_modified",)),
        Technique("T1055", "Process Injection", "Defense Evasion",
                   "Adversary injects code into another process to evade detection.",
                   ("edr_process_injection",)),
        Technique("T1070.001", "Indicator Removal: Clear Windows Event Logs", "Defense Evasion",
                   "Adversary clears event logs to cover tracks.",
                   ("edr_event_log_cleared", "siem_log_clear")),
        Technique("T1110", "Brute Force", "Credential Access",
                   "Adversary attempts many credentials against an account.",
                   ("authentication_failure", "vpn_authentication_failure")),
        Technique("T1110.003", "Brute Force: Password Spraying", "Credential Access",
                   "Adversary tries one password across many accounts.",
                   ("authentication_failure_multi_account",)),
        Technique("T1003", "OS Credential Dumping", "Credential Access",
                   "Adversary dumps credentials from OS memory or files.",
                   ("edr_lsass_access", "edr_credential_dumping_tool")),
        Technique("T1087", "Account Discovery", "Discovery",
                   "Adversary enumerates accounts on a system or domain.",
                   ("edr_account_enumeration", "ad_ldap_enumeration")),
        Technique("T1018", "Remote System Discovery", "Discovery",
                   "Adversary enumerates other systems on the network.",
                   ("edr_network_scan_local",)),
        Technique("T1021.001", "Remote Services: Remote Desktop Protocol", "Lateral Movement",
                   "Adversary uses RDP to move laterally.",
                   ("firewall_rdp_lateral", "rdp_logon_anomalous")),
        Technique("T1021.002", "Remote Services: SMB/Windows Admin Shares", "Lateral Movement",
                   "Adversary uses admin shares to move laterally.",
                   ("edr_smb_lateral_movement",)),
        Technique("T1560", "Archive Collected Data", "Collection",
                   "Adversary compresses/encrypts data prior to exfiltration.",
                   ("edr_archive_utility_suspicious",)),
        Technique("T1071.001", "Application Layer Protocol: Web Protocols", "Command and Control",
                   "Adversary uses HTTP/HTTPS for C2 communication.",
                   ("firewall_c2_beacon", "proxy_suspicious_useragent")),
        Technique("T1071.004", "Application Layer Protocol: DNS", "Command and Control",
                   "Adversary uses DNS for C2 / tunneling.",
                   ("dns_tunneling_suspected", "dns_high_entropy_query")),
        Technique("T1041", "Exfiltration Over C2 Channel", "Exfiltration",
                   "Adversary exfiltrates data over the existing C2 channel.",
                   ("firewall_large_outbound_transfer", "dlp_exfiltration_alert")),
        Technique("T1567.002", "Exfiltration to Cloud Storage", "Exfiltration",
                   "Adversary exfiltrates data to a cloud storage service.",
                   ("cloud_storage_bulk_upload", "casb_unsanctioned_upload")),
        Technique("T1486", "Data Encrypted for Impact", "Impact",
                   "Adversary encrypts data/systems for ransom (ransomware).",
                   ("edr_mass_file_encryption", "edr_ransomware_signature")),
        Technique("T1490", "Inhibit System Recovery", "Impact",
                   "Adversary deletes shadow copies/backups to prevent recovery.",
                   ("edr_shadow_copy_deleted", "edr_vssadmin_delete")),
        Technique("T1531", "Account Access Removal", "Impact",
                   "Adversary locks legitimate users out of accounts/systems.",
                   ("identity_mass_password_reset",)),
        Technique("T1496", "Resource Hijacking", "Impact",
                   "Adversary uses compromised resources for cryptomining etc.",
                   ("edr_cryptomining_process", "cloud_anomalous_compute_spike")),
        Technique("T1098", "Account Manipulation", "Persistence",
                   "Adversary adds credentials/permissions to maintain access.",
                   ("cloud_iam_policy_change_suspicious", "ad_privileged_group_add")),
    ]
}


def get_technique(technique_id: str) -> Technique | None:
    return TECHNIQUES.get(technique_id)


def techniques_for_event_type(event_type: str) -> list[Technique]:
    return [t for t in TECHNIQUES.values() if event_type in t.related_event_types]


def tactic_progression_score(tactics_seen: list[str]) -> float:
    """
    Score 0-1 reflecting how far along the kill chain an incident's
    observed tactics span. A chain touching Initial Access through
    Impact scores much higher than isolated Discovery noise.
    """
    if not tactics_seen:
        return 0.0
    indices = sorted({TACTIC_ORDER.index(t) for t in tactics_seen if t in TACTIC_ORDER})
    if not indices:
        return 0.0
    span = (indices[-1] - indices[0]) + 1
    return round(min(span / len(TACTIC_ORDER), 1.0), 3)
