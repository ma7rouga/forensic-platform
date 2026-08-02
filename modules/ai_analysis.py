import json
import os

try:
    import anthropic
    _CLIENT_AVAILABLE = True
except ImportError:
    _CLIENT_AVAILABLE = False

SAMPLE_ANALYSIS = (
    "Sample analysis (offline mode): The captured memory image shows a process "
    "tree consistent with normal system activity. No high-confidence code injection "
    "was found by malfind, and no active network connections were observed at "
    "capture time. This is placeholder text shown when no API key is configured."
)


def _build_prompt(context: dict) -> str:
    return f"""You are assisting a digital forensics investigator. Below is aggregated
evidence extracted from a memory forensics pipeline (Volatility3, a malware
classifier, a network intrusion classifier, and MITRE ATT&CK keyword mapping).

Write the "Analysis" section of a forensic report: 3-5 short paragraphs.
Be factual and hedge appropriately (say "suggests" / "is consistent with", not
"proves"). Do not invent processes, IPs, or findings that are not in the data below.
If the evidence is inconclusive, say so explicitly.

=== PROCESS TREE SUMMARY ===
{json.dumps(context.get('pstree_summary', {}), indent=2)}

=== MALFIND (INJECTED CODE CANDIDATES) ===
{json.dumps(context.get('malfind', [])[:15], indent=2)}

=== NETWORK CONNECTIONS ===
{json.dumps(context.get('netscan', [])[:15], indent=2)}

=== MALWARE CLASSIFIER VERDICT (MemMal-D2024 model) ===
{json.dumps(context.get('malware_verdict', {}), indent=2)}

=== NETWORK CLASSIFIER VERDICT (CICIDS2017 model) ===
{json.dumps(context.get('network_verdict', {}), indent=2)}

=== MITRE ATT&CK MAPPING ===
{json.dumps(context.get('mitre_mapping', []), indent=2)}
"""


def generate_report_analysis(context: dict) -> str:
    """Entry point matching the rest of the pipeline's pattern: try the real
    tool (LLM API) first, fall back to sample text if unavailable — same
    resilient design as the other stages."""
    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not (_CLIENT_AVAILABLE and api_key):
        return SAMPLE_ANALYSIS

    try:
        client = anthropic.Anthropic(api_key=api_key)
        response = client.messages.create(
            model="claude-sonnet-4-5",
            max_tokens=1000,
            messages=[{"role": "user", "content": _build_prompt(context)}],
        )
        return "".join(
            block.text for block in response.content if block.type == "text"
        )
    except Exception as e:
        print(f"[ai_analysis] LLM call failed, falling back to sample: {e}")
        return SAMPLE_ANALYSIS