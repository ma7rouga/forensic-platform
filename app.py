from theme import inject_theme, real_marker, mock_marker, status_strip, metric_row
import streamlit as st
import json
import os
from modules.memmal_score import score_memory_features
from modules.network_score import score_network_flow
from modules.netscan import run_netscan
from modules.extraction import run_extraction
from modules.injection import run_injection_scan
from modules.malware import run_malware_analysis
from modules.ghidra_analysis import run_ghidra_analysis
from modules.mitre_mapping import map_to_attack
from modules.report import build_markdown_report, save_markdown, save_pdf
from modules.volatility_parser import load_pstree, load_netscan, summarize_pstree, load_malfind
from modules.ai_analysis import generate_report_analysis
from modules.registry import load_registry_summary

st.set_page_config(page_title="REN 人", layout="wide")
inject_theme()

if "results" not in st.session_state:
    st.session_state.results = {}

st.title("REN 人")
st.caption("AI-assisted forensic investigation platform")

status_strip([
    ("Volatility3", bool(load_pstree("pstree.json"))),
    ("Malfind", bool(load_malfind("malfind.json"))),
    ("Ghidra", False),
    ("Registry", False),
    ("LLM (Claude)", bool(os.environ.get("ANTHROPIC_API_KEY"))),
])

st.sidebar.header("Target configuration")
target_ip = st.sidebar.text_input("Target IP (netscan)", "127.0.0.1")
memory_image = st.sidebar.text_input("Memory image path (optional)", "")
binary_path = st.sidebar.text_input("Suspect binary path (optional)", "")
hive_path = st.sidebar.text_input("Registry hive path (optional)", "")

tabs = st.tabs(["Collection", "Detection", "Analysis", "Report"])

# ---------------------------------------------------------------- Collection
with tabs[0]:
    st.subheader("Network scan")
    if st.button("Run network scan"):
        with st.spinner("Scanning..."):
            st.session_state.results["netscan"] = run_netscan(target_ip)
    if "netscan" in st.session_state.results:
        mock_marker("sample data") if not target_ip or target_ip == "127.0.0.1" else real_marker("live result")
        st.json(st.session_state.results["netscan"])

    st.divider()
    st.subheader("Memory extraction")
    if st.button("Run extraction"):
        with st.spinner("Extracting..."):
            st.session_state.results["extraction"] = run_extraction(memory_image or None)
    if "extraction" in st.session_state.results:
        real_marker("live result") if memory_image else mock_marker("sample data")
        st.json(st.session_state.results["extraction"])

    st.divider()
    st.subheader("Volatility3 capture")
    real_procs = load_pstree("pstree.json")
    real_conns = load_netscan("netscan.json")
    if real_procs:
        real_marker(f"{len(real_procs)} real processes loaded")
        st.json(summarize_pstree(real_procs))
    if not real_conns:
        mock_marker("no active connections at capture time")

# ----------------------------------------------------------------- Detection
with tabs[1]:
    st.subheader("Code injection detection")
    if st.button("Run injection scan"):
        with st.spinner("Scanning..."):
            st.session_state.results["injection"] = run_injection_scan(memory_image or None)
    if "injection" in st.session_state.results:
        real_marker("live result") if memory_image else mock_marker("sample data")
        st.json(st.session_state.results["injection"])

    real_malfind = load_malfind("malfind.json")
    if real_malfind:
        real_marker(f"{len(real_malfind)} suspicious region(s) — Volatility3 malfind")
        st.session_state.results["malfind_real"] = real_malfind
        st.json(real_malfind[:10])

    st.divider()
    st.subheader("Malware triage")
    if st.button("Run malware scoring"):
        with st.spinner("Analyzing..."):
            st.session_state.results["malware"] = run_malware_analysis(binary_path or None)
    if "malware" in st.session_state.results:
        real_marker("live result") if binary_path else mock_marker("sample data")
        st.json(st.session_state.results["malware"])

    st.divider()
    st.subheader("MemMal-D2024 — memory feature classifier")
    if st.button("Run MemMal scoring"):
        with st.spinner("Analyzing..."):
            st.session_state.results["memmal"] = score_memory_features()
    if "memmal" in st.session_state.results:
        st.json(st.session_state.results["memmal"])

    st.divider()
    st.subheader("CICIDS2017 — network flow classifier")
    if st.button("Run network scoring"):
        with st.spinner("Analyzing..."):
            st.session_state.results["network_ai"] = score_network_flow()
    if "network_ai" in st.session_state.results:
        st.json(st.session_state.results["network_ai"])

# ------------------------------------------------------------------ Analysis
with tabs[2]:
    st.subheader("Ghidra decompilation")
    if st.button("Run Ghidra analysis"):
        with st.spinner("Decompiling..."):
            st.session_state.results["ghidra"] = run_ghidra_analysis(binary_path or None)
    if "ghidra" in st.session_state.results:
        real_marker("live result") if binary_path else mock_marker("sample data")
        st.json(st.session_state.results["ghidra"])

    st.divider()
    st.subheader("MITRE ATT&CK mapping")
    if st.button("Generate ATT&CK mapping"):
        blob = json.dumps(st.session_state.results, default=str)
        st.session_state.results["mitre"] = map_to_attack(blob)
    if "mitre" in st.session_state.results:
        for tech in st.session_state.results["mitre"]:
            st.markdown(f"**{tech['technique_id']} — {tech['technique_name']}**  \nTactic: {tech['tactic']}")

    st.divider()
    st.subheader("Registry")
    if st.button("Load registry"):
        with st.spinner("Reading..."):
            st.session_state.results["registry"] = load_registry_summary(hive_path or None)
    if "registry" in st.session_state.results:
        real_marker("live result") if hive_path else mock_marker("sample data")
        st.json(st.session_state.results["registry"])

# -------------------------------------------------------------------- Report
with tabs[3]:
    st.subheader("Final report")

    metric_row([
        (str(len(load_pstree("pstree.json"))), "processes"),
        (str(len(load_malfind("malfind.json"))), "injection sites"),
        (str(len(st.session_state.results.get("mitre", []))), "ATT&CK techniques"),
    ])

    if st.button("Generate AI analysis"):
        with st.spinner("Generating analysis..."):
            context = {
                "pstree_summary": summarize_pstree(load_pstree("pstree.json")),
                "malfind": load_malfind("malfind.json"),
                "netscan": load_netscan("netscan.json"),
                "malware_verdict": st.session_state.results.get("memmal", {}),
                "network_verdict": st.session_state.results.get("network_ai", {}),
                "mitre_mapping": st.session_state.results.get("mitre", []),
            }
            st.session_state.results["ai_analysis"] = generate_report_analysis(context)
    if "ai_analysis" in st.session_state.results:
        st.markdown("**AI-generated analysis:**")
        st.write(st.session_state.results["ai_analysis"])

    st.divider()
    if st.button("Generate report"):
        md = build_markdown_report(st.session_state.results)
        os.makedirs("output", exist_ok=True)
        md_path = save_markdown(md, "output/report.md")
        pdf_path = save_pdf(md, "output/report.pdf")
        st.session_state.results["report_md"] = md
        st.success(f"Report generated: {md_path}" + (f" and {pdf_path}" if pdf_path else ""))
    if "report_md" in st.session_state.results:
        st.markdown(st.session_state.results["report_md"])
        st.download_button("Download report (Markdown)",
                            st.session_state.results["report_md"],
                            file_name="rapport.md")