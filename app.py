from theme import inject_theme
import streamlit as st
import json
import os
from modules.memmal_score import score_memory_features
from modules.network_score import score_network_flow
from modules.netscan import run_netscan
from modules.extraction import run_extraction
from modules.injection import run_injection_scan
from modules.injection import run_injection_scan
from modules.malware import run_malware_analysis
from modules.ghidra_analysis import run_ghidra_analysis
from modules.mitre_mapping import map_to_attack
from modules.report import build_markdown_report, save_markdown, save_pdf
from modules.volatility_parser import load_pstree, load_netscan, summarize_pstree, load_malfind
from modules.ai_analysis import generate_report_analysis
from modules.registry import load_registry_summary
st.set_page_config(page_title="Forensic AI Platform", layout="wide")
inject_theme()
if "results" not in st.session_state:
    st.session_state.results = {}

st.title("foren")
st.caption("platforme dinvestigation")

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
          "6. MITRE ATT&CK", "7. Registre", "8. Rapport"]
tabs = st.tabs(stages)

# ---- Stage 1: Netscan ----
with tabs[0]:
    st.subheader("Netscan")
    if st.button("Lancer le scan réseau"):
        with st.spinner("Scan en cours..."):
            st.session_state.results["netscan"] = run_netscan(target_ip)
    if "netscan" in st.session_state.results:
        st.json(st.session_state.results["netscan"])
    st.markdown("---")
    st.subheader("Score IA — CICIDS2017 (flux réseau)")
    if st.button("Lancer le scoring réseau IA"):
        with st.spinner("Analyse en cours..."):
            st.session_state.results["network_ai"] = score_network_flow()
    if "network_ai" in st.session_state.results:
        st.json(st.session_state.results["network_ai"])
    st.markdown("---")
    st.subheader("capture Volatility")
    real_procs = load_pstree("pstree.json")
    real_conns = load_netscan("netscan.json")
    if real_procs:
        st.success(f"{len(real_procs)} processus réels chargés depuis pstree.json")
        st.json(summarize_pstree(real_procs))
    if not real_conns:
        st.info("netscan.json: aucune connexion active au moment de la capture.")
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

    st.markdown("---")
    st.subheader("Résultats réels — Volatility3 malfind")
    real_malfind = load_malfind("malfind.json")
    if real_malfind:
        st.success(f"{len(real_malfind)} zone(s) suspecte(s) détectée(s) (malfind réel)")
        st.session_state.results["malfind_real"] = real_malfind
        st.json(real_malfind[:10])
    else:
        st.info("malfind.json: aucune donnée réelle trouvée.")

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

    st.markdown("---")
    st.subheader("Score IA — MemMal-D2024 (features mémoire)")
    if st.button("Lancer le scoring MemMal"):
        with st.spinner("Analyse en cours..."):
            st.session_state.results["memmal"] = score_memory_features()
    if "memmal" in st.session_state.results:
        st.json(st.session_state.results["memmal"])
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
# ---- Stage 7: Registre ----
with tabs[6]:
    st.subheader("Analyse du registre")
    hive_path = st.text_input("Chemin vers une ruche exportée (optionnel)", "")
    if st.button("Charger le registre"):
        with st.spinner("Lecture en cours..."):
            st.session_state.results["registry"] = load_registry_summary(hive_path or None)
    if "registry" in st.session_state.results:
        st.json(st.session_state.results["registry"])
# ---- Stage 8: Rapport ----
with tabs[7]:
    st.subheader("Rapport final")

    if st.button("Générer l'analyse IA"):
        with st.spinner("L'IA rédige l'analyse..."):
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
        st.markdown("**Analyse générée par l'IA :**")
        st.write(st.session_state.results["ai_analysis"])

    if st.button("Générer le rapport"):
        md = build_markdown_report(st.session_state.results)
        ...
