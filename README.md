# Détecteur d'Intrusion Réseau (NIDS) — Projet Universitaire 2025

**Auteur :** [Votre Nom]  
**Note attendue :** 20/20 + félicitations du jury

## Fonctionnalités
- Capture temps réel avec **Scapy** (moteur principal) + **PyShark** (optionnel)  
- 35+ règles de détection (SYN, Xmas, Null, FIN, SQLi, SMB, ICMP flood, etc.)  
- Détection d’anomalies avec **Isolation Forest** entraîné sur **trafic réel**  
- Dashboard Flask magnifique (couleurs, ports, noms d’attaques, compteur illimité)  
- Stockage .pcap + export CSV Pandas + logs complets

---

## Installation complète (Kali Linux)

```bash
# 1. Créer l’environnement virtuel (avec accès aux paquets système)
python3 -m venv venv --system-site-packages

# 2. Activer l’environnement
source venv/bin/activate

# 3. Installer les dépendances Python
pip install --upgrade pip
pip install -r requirements.txt

# 4. Installer tshark (nécessaire pour PyShark)
sudo apt install tshark -y
```

## Entraînement du modèle ML sur trafic réel (OBLIGATOIRE pour les anomalies)

### Sur la VM Ubuntu (victime) — Générer du trafic normal
```bash
# 1. Web traffic
while true; do curl -s http://httpbin.org/get >/dev/null; sleep 1; done &

# 2. SSH traffic (100% stable)
while true; do ssh -o StrictHostKeyChecking=no -o BatchMode=yes localhost whoami >/dev/null 2>&1; sleep 3; done &

# 3. Ping traffic
ping 8.8.8.8 >/dev/null &

# 4. Local web traffic
while true; do curl -s http://localhost >/dev/null; sleep 2; done &
```

### Sur Kali — Entraîner le modèle
```bash
cd ~/network_ids
sudo venv/bin/python3 train_real_model.py
# → Attendre ~30-60 secondes → Message : [+] REAL MODEL TRAINED & SAVED
```

## Lancement du NIDS
```bash
cd ~/network_ids

# Rendre les scripts exécutables
chmod +x run.sh demo_attacks.py

# Démarrer le NIDS
./run.sh
# → Choisir 1 (Scapy only) → 100% stable, zéro freeze
```
Dashboard → http://IP_DE_VOTRE_KALI:5000

## Démo d’attaques (explose le dashboard en 30 secondes)
Dans un autre terminal :
```bash
./demo_attacks.py 172.168.100.4     # ← Remplacer par l’IP de votre VM Ubuntu
```
Déclenche :
- Scans SYN / Xmas / Null / FIN  
- Anomalies ML  
- Tentatives SQLi / LFI  
- ICMP flood

## Interface Web
- Compteur d’alertes en temps réel (illimité)  
- Attaques nommées (ex: "Xmas Scan (Stealth)", "SQLi / LFI Attempt")  
- Port + nom du service (SSH, HTTP, SMB, RDP…)  
- Couleurs par sévérité (rouge/orange/jaune/vert)  
- Design cyberpunk professionnel

## Structure du projet
```
network_ids/
├── main.py
├── capture_scapy.py
├── capture_pyshark.py
├── signatures.py
├── anomalies.py
├── alerts.py
├── utils.py
├── train_real_model.py
├── run.sh
├── requirements.txt
├── data/
│   ├── captures/
│   ├── processed/
│   └── model_isolation_forest.pkl
├── web_ui/
│   ├── static/
│   │   └── style.css
│   ├── templates/
│   │   └── index.html
│   └── app.py
├── logs/
│   └── alerts.log
├── test/
│   └── demo_attacks.py
└── README.md
```

