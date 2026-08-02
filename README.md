# REN 人 — AI-Assisted Forensic Investigation Platform

## What this is

An end-to-end forensic investigation pipeline: `netscan → extraction →
injection → malware triage → ghidra → mitre_attack → registry → AI analysis → report`

Each stage is an independent Python module. If the real tool (Volatility3,
Ghidra, a target binary, a registry hive) isn't available or no input is
provided, the module automatically falls back to realistic sample data —
**the full pipeline always runs and produces a report, regardless of the
demo environment.**

The UI marks every result as either a live result or sample data, so this
is never ambiguous to whoever is reviewing it.

## Installation
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
Optional environment variables:
- `ANTHROPIC_API_KEY` — enables the live LLM analysis stage. Without it, the
  report falls back to placeholder analysis text.
- `EMBER_MODEL_PATH` — not currently used (EMBER integration removed; malware
  triage uses heuristic scoring only).

## Architecture

- **Orchestrator**: `app.py` (Streamlit) — chains the stages, keeps state in
  session, triggers report generation.
- **Independent modules**: each stage is isolated in `modules/<stage>.py`
  with a clear entry function — replacing sample data with the real tool
  only ever touches that one file, never the rest of the pipeline. That's
  the point: the architectural core is stable, tool integration is
  incremental work behind an interface that's already fixed.
- **Resilient design**: each module tries the real tool first (subprocess
  or direct parsing), and falls back to sample data otherwise — so the
  pipeline never breaks during a demo.

## Status

| Stage | State |
| --- | --- |
| Netscan | pure-Python socket scan (works everywhere); real process list via Volatility3 pstree.json |
| Extraction | wired to real Volatility3 output when a memory image / dump files are present |
| Injection | real Volatility3 malfind results integrated (`windows.malware.malfind.Malfind`) |
| Malware triage | heuristic scoring (entropy, magic bytes, suspicious API strings) — real when given a file path |
| MemMal-D2024 / CICIDS2017 | trained classifiers, wired into the pipeline |
| Registry | module added (`regipy`) — real when given an exported hive, sample data otherwise |
| Ghidra | sample decompiled snippet — real integration requires `GHIDRA_HOME` + `analyzeHeadless`, not completed |
| MITRE ATT&CK | static keyword mapping |
| AI analysis | LLM (Claude) reads the aggregated pipeline results and writes the report's analysis section |
| Autopsy | not integrated |

See `REPORT_NOTES.md` for the full methodology and scope notes.