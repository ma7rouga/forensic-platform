# Plateforme Forensique d'Investigation basée sur l'IA — Core Pipeline

## Ce que c'est
Le squelette fonctionnel de bout en bout du pipeline :
`netscan → extraction → injection → ghidra → mitre_attack → rapport`

Chaque étape est un module Python indépendant. Si l'outilréel (nmap,
Volatility3, Ghidra) n'est pas installé ou qu'aucune image/binaire n'est
fourni, le module retombe automatiquement sur des données d'exemple
réalistes — **le pipeline complet tourne et produit un rapport quel que
soit l'environnement de démo.**

## Installation 
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```

## L'architecture
- **Orchestrateur** : `app.py` (Streamlit) — chaîne les 6 étapes, garde
  l'état en session, déclenche la génération du rapport.
- **Modules indépendants** : chaque étape est isolée dans
  `modules/<stage>.py` avec une fonction d'entrée claire — ça veut dire
  que remplacer les données d'exemple par le vrai outil ne touche QUE ce
  fichier, jamais le reste du pipeline. C'est le point à vendre : le
  cœur architectural est stable, l'intégration des outils est un travail
  incrémental derrière une interface déjà fixée.
- **Design résilient** : chaque module essaie l'outil réel en premier
  (subprocess), et retombe sur des données d'exemple sinon — donc le
  pipeline ne casse jamais en démo.

## Ce qui reste à faire (prochaine sprint)
| Étape | Aujourd'hui | Prochaine étape |
|---|---|---|
| Netscan | scan socket pur Python (fonctionne partout) | brancher `python-nmap` pour scan de service/version complet |
| Extraction | données d'exemple | tester avec une vraie image mémoire (.raw/.vmem) + Volatility3 installé |
| Injection | données d'exemple (malfind simulé) | brancher le plugin réel `windows.malfind` de Volatility3 |
| Ghidra | snippet décompilé d'exemple | installer Ghidra, définir `GHIDRA_HOME`, tester `analyzeHeadless` sur un vrai binaire |
| Registre | non branché encore | ajouter `modules/registry.py` avec la lib `regipy` pour parser une ruche réelle |
| Autopsy | non branché encore | soit lancer Autopsy en parallèle sur le disque image, soit importer son export TSK/bodyfile |
| MITRE | mapping statique par mots-clés | remplacer par la lib `mitreattack-python` pour un mapping complet au framework STIX |
| IA | pas encore ajoutée | c'est le prochain gros morceau : un LLM qui lit les résultats agrégés du pipeline et rédige la section "analyse" du rapport automatiquement |

