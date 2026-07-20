"""
modules/mitre_mapping.py

Upgrade from pure keyword-matching to the REAL, official MITRE ATT&CK
dataset via the mitreattack-python library (maintained by MITRE itself).

How it works:
  1. Keyword detection (unchanged idea, expanded table) scans the pipeline's
     aggregated JSON blob to decide WHICH techniques are relevant. This part
     is still a heuristic — no library replaces "deciding what's suspicious"
     for you, that's still your detection logic.
  2. Each detected technique ID is then enriched with the REAL, current,
     official name/tactic/description straight from MITRE's own STIX 2.0
     dataset, instead of a hardcoded string in this file. If MITRE updates
     a technique's name or tactic, your report reflects it automatically.
"""

import os
import re

STIX_PATH = os.environ.get("ATTACK_STIX_PATH", "enterprise-attack.json")

# Keyword -> technique ID. This is the "detection" layer: what in the
# pipeline's findings should trigger which technique being reported.
KEYWORD_TO_TECHNIQUE = {
    "process_injection": "T1055",
    "injection": "T1055",
    "malfind": "T1055",
    "svchost": "T1036",
    "masquerad": "T1036",
    "powershell": "T1059.001",
    "macro": "T1566.001",
    "phishing": "T1566.001",
    "c2": "T1071.001",
    "beacon": "T1071.001",
    "suspicious connection": "T1071.001",
    "log deletion": "T1070.004",
    "logs_reseau": "T1070.004",
    "deleted": "T1070.004",
    "usb": "T1091",
}

# Fallback data (used only if enterprise-attack.json isn't downloaded yet,
# or the library fails to load it for any reason).
FALLBACK_TECHNIQUES = {
    "T1055": {"name": "Process Injection", "tactic": "Defense Evasion"},
    "T1036": {"name": "Masquerading", "tactic": "Defense Evasion"},
    "T1059.001": {"name": "Command and Scripting Interpreter: PowerShell", "tactic": "Execution"},
    "T1566.001": {"name": "Phishing: Spearphishing Attachment", "tactic": "Initial Access"},
    "T1071.001": {"name": "Application Layer Protocol: Web Protocols", "tactic": "Command and Control"},
    "T1070.004": {"name": "Indicator Removal: File Deletion", "tactic": "Defense Evasion"},
    "T1091": {"name": "Replication Through Removable Media", "tactic": "Initial Access / Lateral Movement"},
}

_mitre_data = None
_load_attempted = False


def _load_mitre_data():
    """Lazily loads the real MITRE STIX dataset. Returns None (tries only
    once) if the file/library isn't available — callers fall back to the
    static table automatically."""
    global _mitre_data, _load_attempted
    if _load_attempted:
        return _mitre_data
    _load_attempted = True

    if not os.path.exists(STIX_PATH):
        return None
    try:
        from mitreattack.stix20 import MitreAttackData
        _mitre_data = MitreAttackData(STIX_PATH)
    except Exception as e:  # noqa: BLE001 - optional enrichment tier
        print(f"[mitre_mapping] Could not load {STIX_PATH} ({e}); using static fallback table.")
        _mitre_data = None
    return _mitre_data


def _lookup_technique(attack_id: str) -> dict:
    """Returns {name, tactic, source} for a technique ID — real MITRE data
    if available, static fallback otherwise."""
    mitre_data = _load_mitre_data()
    if mitre_data is not None:
        try:
            obj = mitre_data.get_object_by_attack_id(attack_id, "attack-pattern")
            if obj is not None:
                phases = getattr(obj, "kill_chain_phases", [])
                tactics = [p["phase_name"].replace("-", " ").title() for p in phases] or ["—"]
                return {"name": obj.name, "tactic": " / ".join(tactics), "source": "real"}
        except Exception as e:  # noqa: BLE001
            print(f"[mitre_mapping] Lookup failed for {attack_id} ({e}); using static fallback.")

    fallback = FALLBACK_TECHNIQUES.get(attack_id, {"name": attack_id, "tactic": "—"})
    return {**fallback, "source": "static-fallback"}


def map_to_attack(blob: str) -> list[dict]:
    """Scans the aggregated pipeline JSON (as a string) for keyword signals,
    and returns a list of {technique_id, technique_name, tactic, source}
    dicts — same shape app.py already expects, so no changes needed there.
    """
    text = blob.lower()
    matched_ids = set()

    for keyword, attack_id in KEYWORD_TO_TECHNIQUE.items():
        if re.search(re.escape(keyword.lower()), text):
            matched_ids.add(attack_id)

    results = []
    for attack_id in sorted(matched_ids):
        info = _lookup_technique(attack_id)
        results.append({
            "technique_id": attack_id,
            "technique_name": info["name"],
            "tactic": info["tactic"],
            "source": info["source"],  # "real" (from MITRE's own data) or "static-fallback"
        })

    return results