# Décodeur IZAR LRZ102 — V2.1 avec dépôt de documents

Fichiers inclus :
- app.py : portail Streamlit avec navigation
- decoder.py : décodage métier + EC1 simplifiée
- security.py : déchiffrement Mode 8
- requirements.txt : dépendances

Lancement :
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
python -m streamlit run app.py
