"""
Stage 6: RAPPORT
Compiles every stage's output into a Markdown report, and a PDF if
fpdf2 is installed (pure-Python, no external binary needed).
"""
from datetime import datetime
import os

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


def build_markdown_report(pipeline_results: dict) -> str:
    lines = [
        "# Rapport d'Investigation Forensique",
        f"_Généré le {datetime.now().strftime('%Y-%m-%d %H:%M')}_",
        "",
        "## 1. Netscan",
        f"```\n{pipeline_results.get('netscan', {})}\n```",
        "",
        "## 2. Extraction (mémoire)",
        f"```\n{pipeline_results.get('extraction', {})}\n```",
        "",
        "## 3. Détection d'injection",
        f"```\n{pipeline_results.get('injection', {})}\n```",
        "",
        "## 4. Analyse Ghidra",
        f"```\n{pipeline_results.get('ghidra', {})}\n```",
        "",
        "## 5. Cartographie MITRE ATT&CK",
    ]
    for tech in pipeline_results.get("mitre", []):
        lines.append(
            f"- **{tech['technique_id']} — {tech['technique_name']}** "
            f"(Tactique: {tech['tactic']})"
        )
    lines += ["", "## 6. Conclusion",
              "Voir les indicateurs ci-dessus. Étapes suivantes : intégration "
              "live des outils marqués 'sample-data'."]
    return "\n".join(lines)


def save_markdown(content: str, out_path: str) -> str:
    with open(out_path, "w") as f:
        f.write(content)
    return out_path


def _wrap_long_line(line: str, max_chars: int = 90) -> list:
    """Force-break any single 'word' (e.g. long JSON blobs, paths with no
    spaces) that would otherwise be too wide for fpdf to render, which is
    what causes 'Not enough horizontal space' crashes."""
    if len(line) <= max_chars:
        return [line]
    return [line[i:i + max_chars] for i in range(0, len(line), max_chars)]


def save_pdf(content: str, out_path: str) -> str:
    if not HAS_FPDF:
        return None
    try:
        pdf = FPDF()
        pdf.add_page()
        pdf.set_font("Courier", size=9)
        pdf.set_auto_page_break(auto=True, margin=15)
        for raw_line in content.split("\n"):
            for chunk in _wrap_long_line(raw_line):
                safe_chunk = chunk.encode("latin-1", "replace").decode("latin-1")
                pdf.multi_cell(0, 5, safe_chunk)
        pdf.output(out_path)
        return out_path
    except Exception as e:
        print(f"[report.py] PDF generation failed, continuing without it: {e}")
        return None