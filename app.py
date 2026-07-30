from theme import inject_theme
import streamlit as st
import json
import os

from modules.netscan import run_netscan
from modules.extraction import run_extraction
from modules.injection import run_injection_scan
from modules.injection import run_injection_scan
from modules.malware import run_malware_analysis
from modules.ghidra_analysis import run_ghidra_analysis
from modules.mitre_mapping import map_to_attack
from modules.report import build_markdown_report, save_markdown, save_pdf

st.set_page_config(page_title="Forensic AI Platform", layout="wide")
inject_theme()
if "results" not in st.session_state:
    st.session_state.results = {}

st.title("🔍 Plateforme Forensique d'Investigation — Core Pipeline")
st.caption("netscan → extraction → injection → ghidra → mitre_attack → rapport")

st.sidebar.header("Configuration de la cible")
target_ip = st.sidebar.text_input("IP cible (netscan)", "127.0.0.1")
memory_image = st.sidebar.text_input("Chemin image mémoire (optionnel)", "")
binary_path = st.sidebar.text_input("Chemin binaire suspect pour Ghidra (optionnel)", "")

st.sidebar.markdown("---")
st.sidebar.info(
    "Les étapes sans outil live installé retombent automatiquement sur des "
    "données d'exemple réalistes — le pipeline reste démontrable de bout en "
    "bout quel que soit l'environnement."
)

stages = ["1. Netscan", "2. Extraction", "3. Injection", "4. Malware Detection", "5. Ghidra",
          "6. MITRE ATT&CK", "7. Rapport"]
tabs = st.tabs(stages)

# ---- Stage 1: Netscan ----
with tabs[0]:
    st.subheader("Netscan")
    if st.button("Lancer le scan réseau"):
        with st.spinner("Scan en cours..."):
            st.session_state.results["netscan"] = run_netscan(target_ip)
    if "netscan" in st.session_state.results:
        st.json(st.session_state.results["netscan"])

# ---- Stage 2: Extraction ----
with tabs[1]:
    st.subheader("Extraction mémoire")
    if st.button("Lancer l'extraction"):
        with st.spinner("Extraction en cours..."):
            st.session_state.results["extraction"] = run_extraction(memory_image or None)
    if "extraction" in st.session_state.results:
        st.json(st.session_state.results["extraction"])

# ---- Stage 3: Injection ----
with tabs[2]:
    st.subheader("Détection d'injection de code")
    if st.button("Lancer la détection d'injection"):
        with st.spinner("Analyse en cours..."):
            st.session_state.results["injection"] = run_injection_scan(memory_image or None)
    if "injection" in st.session_state.results:
        st.json(st.session_state.results["injection"])

# ---- Stage 4: Malware Detection ----
with tabs[3]:
    st.subheader("Analyse malware — scoring + IA")
    if st.button("Lancer le scoring malware"):
        with st.spinner("Analyse en cours..."):
            st.session_state.results["malware"] = run_malware_analysis(binary_path or None)
    if "malware" in st.session_state.results:
        result = st.session_state.results["malware"]
        st.json(result)
        if result.get("mlAvailable"):
            st.success(f"Modèle EMBER actif — probabilité malveillante : {result['ml']['maliciousProbability']}")
        else:
            st.info("Modèle EMBER non chargé (EMBER_MODEL_PATH non défini) — score heuristique utilisé seul.")

# ---- Stage 5: Ghidra ----
with tabs[4]:
    st.subheader("Analyse Ghidra")
    if st.button("Lancer l'analyse Ghidra"):
        with st.spinner("Décompilation en cours..."):
            st.session_state.results["ghidra"] = run_ghidra_analysis(binary_path or None)
    if "ghidra" in st.session_state.results:
        st.json(st.session_state.results["ghidra"])

# ---- Stage 6: MITRE ----
with tabs[5]:
    st.subheader("Cartographie MITRE ATT&CK")
    if st.button("Générer la cartographie ATT&CK"):
        blob = json.dumps(st.session_state.results, default=str)
        st.session_state.results["mitre"] = map_to_attack(blob)
    if "mitre" in st.session_state.results:
        for tech in st.session_state.results["mitre"]:
            st.markdown(f"**{tech['technique_id']} — {tech['technique_name']}**  \n"
                        f"Tactique : {tech['tactic']}")

# ---- Stage 7: Rapport ----
with tabs[6]:
    st.subheader("Rapport final")
    if st.button("Générer le rapport"):
        md = build_markdown_report(st.session_state.results)
        os.makedirs("output", exist_ok=True)
        md_path = save_markdown(md, "output/rapport.md")
        pdf_path = save_pdf(md, "output/rapport.pdf")
        st.session_state.results["report_md"] = md
        st.success(f"Rapport généré : {md_path}" + (f" et {pdf_path}" if pdf_path else ""))
    if "report_md" in st.session_state.results:
        st.markdown(st.session_state.results["report_md"])
        st.download_button("Télécharger le rapport (Markdown)",
                            st.session_state.results["report_md"],
                            file_name="rapport.md")
