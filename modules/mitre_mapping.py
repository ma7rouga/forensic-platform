"""
Stage 5: MITRE ATT&CK MAPPING
Takes indicators found in earlier stages (injected code, suspicious
APIs, registry persistence, network beaconing) and maps them to
ATT&CK technique IDs. This is a static local lookup table so it needs
no internet access and runs instantly.
"""

TECHNIQUE_RULES = [
    {
        "keyword": "RWX region",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion / Privilege Escalation",
    },
    {
        "keyword": "Reflective",
        "technique_id": "T1055.001",
        "technique_name": "Dynamic-link Library Injection",
        "tactic": "Defense Evasion",
    },
    {
        "keyword": "CreateRemoteThread",
        "technique_id": "T1055",
        "technique_name": "Process Injection",
        "tactic": "Defense Evasion",
    },
    {
        "keyword": "WSAStartup",
        "technique_id": "T1071",
        "technique_name": "Application Layer Protocol (C2)",
        "tactic": "Command and Control",
    },
    {
        "keyword": "Run\\",
        "technique_id": "T1547.001",
        "technique_name": "Registry Run Keys / Startup Folder",
        "tactic": "Persistence",
    },
    {
        "keyword": "powershell.exe",
        "technique_id": "T1059.001",
        "technique_name": "PowerShell",
        "tactic": "Execution",
    },
]


def map_to_attack(findings_text: str) -> list:
    """findings_text: any blob of text gathered from earlier stages
    (findings, decompiled code, registry keys...) — we scan for
    keywords and return matched ATT&CK techniques, deduplicated."""
    matched = {}
    for rule in TECHNIQUE_RULES:
        if rule["keyword"].lower() in findings_text.lower():
            matched[rule["technique_id"]] = rule
    return list(matched.values())
