
from datetime import datetime

try:
    from fpdf import FPDF
    HAS_FPDF = True
except ImportError:
    HAS_FPDF = False


def build_markdown_report(pipeline_results: dict) -> str:
    lines = [
        "# Forensic Investigation Report",
        f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M')}_",
        "",
        "## 1. Network scan",
        f"```\n{pipeline_results.get('netscan', {})}\n```",
        "",
        "## 2. Memory extraction",
        f"```\n{pipeline_results.get('extraction', {})}\n```",
        "",
        "## 3. Code injection detection",
        f"```\n{pipeline_results.get('injection', {})}\n```",
        "",
        "## 3b. Live results — Volatility3 malfind",
    ]
    real_malfind = pipeline_results.get("malfind_real", [])
    if real_malfind:
        lines.append(f"{len(real_malfind)} suspicious region(s) detected on real memory capture:")
        for m in real_malfind[:10]:
            lines.append(f"- PID {m.get('pid')} ({m.get('process')}) — protection: {m.get('protection')}")
    else:
        lines.append("No live malfind data available for this run.")

    lines += [
        "",
        "## 4. Ghidra analysis",
        f"```\n{pipeline_results.get('ghidra', {})}\n```",
        "",
        "## 5. MITRE ATT&CK mapping",
    ]
    for tech in pipeline_results.get("mitre", []):
        lines.append(f"- **{tech['technique_id']} — {tech['technique_name']}** (Tactic: {tech['tactic']})")

    lines += ["", "## 6. Registry"]
    registry = pipeline_results.get("registry")
    lines.append(f"```\n{registry}\n```" if registry else "Registry not analyzed for this run.")

    lines += ["", "## 7. Analysis (AI)"]
    ai_analysis = pipeline_results.get("ai_analysis")
    lines.append(ai_analysis if ai_analysis else "AI analysis not generated for this run.")

    lines += ["", "## 8. Conclusion",
              "See indicators and AI analysis above. Sections still marked "
              "'sample data' indicate a stage where the real tool was not "
              "available in this environment — the underlying pipeline is "
              "already wired to accept live input for those stages."]
    return "\n".join(lines)


def save_markdown(content: str, out_path: str) -> str:
    with open(out_path, "w") as f:
        f.write(content)
    return out_path


def _wrap_long_line(line: str, max_chars: int = 90) -> list:
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