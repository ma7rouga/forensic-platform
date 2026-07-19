# Plateforme Forensique d'Investigation basée sur l'IA — Core Pipeline

## Ce que c'est
Le squelette fonctionnel de bout en bout du pipeline :
`netscan → extraction → injection → ghidra → mitre_attack → rapport`

Chaque étape est un module Python indépendant. Si l'outil réel (nmap,
Volatility3, Ghidra) n'est pas installé ou qu'aucune image/binaire n'est
fourni, le module retombe automatiquement sur des données d'exemple
réalistes — **le pipeline complet tourne et produit un rapport quel que
soit l'environnement de démo.**

## Installation (ce soir)
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
streamlit run app.py
```
Ça ouvre l'interface dans le navigateur. Clique sur chaque onglet dans
l'ordre du pipeline, lance chaque étape, puis génère le rapport final.

## Pour la démo de demain
1. Lance `streamlit run app.py` **avant** d'arriver — teste que ça tourne.
2. Montre le flux complet : clique les 6 boutons dans l'ordre, montre que
   chaque étape alimente la suivante (les résultats s'accumulent dans
   `st.session_state`).
3. Génère et télécharge le rapport final — c'est ta preuve tangible
   ("quelque chose de physique").
4. Sois transparent sur ce qui est "sample-data" vs "live" — vois la
   section "Ce qui reste à faire" ci-dessous. Un superviseur préfère un
   plan honnête à une fausse promesse de tout-fonctionnel.

## Comment parler de l'architecture à ton superviseur
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

## Ce qui reste à faire (prochaine sprint — sois honnête là-dessus)
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

## Où branche "Autopsy" et "Registre" dans ce pipeline ?
Ce ne sont pas encore des étapes séparées dans le code — à clarifier avec
ton superviseur, mais l'interprétation la plus logique :
- **Autopsy** : probablement en parallèle de `extraction` (analyse disque
  vs analyse mémoire) — on pourrait ajouter `modules/disk_triage.py` qui
  importe l'export Autopsy (bodyfile/TSK) en étape 2bis.
- **Registre** : sous-étape d'`extraction`/`injection` côté persistance
  (clés Run, services) — `modules/registry.py` avec `regipy`, alimente
  aussi la cartographie MITRE (T1547.001).

Pose la question demain : "j'ai supposé que Registre et Autopsy sont des
sous-modules d'extraction plutôt que des étapes séparées du pipeline
principal — est-ce correct ?" — ça montre que tu as réfléchi à
l'architecture, pas juste codé au hasard.
