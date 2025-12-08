# 🛡️ Network Intrusion Detection System (NIDS)
### University Project 2025

<div align="center">

**Author:** Mohamed Taher BORGI  

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/License-Academic-green.svg)]()
[![Status](https://img.shields.io/badge/Status-Production-success.svg)]()

</div>

---

## 🚀 Features

- **Real-time packet capture** using **Scapy** (main engine) + **PyShark** (optional)
- **35+ signature rules** for detecting:
  - Port scans (SYN, Xmas, Null, FIN)
  - SQL Injection & LFI attacks
  - SMB exploits
  - ICMP floods
  - And much more...
- **Anomaly detection** powered by **Isolation Forest** ML model trained on **real network traffic**
- **Beautiful Flask web dashboard** featuring:
  - Color-coded severity levels
  - Port names and service identification
  - Attack descriptions
  - Unlimited real-time counter
- **Automatic packet storage** (.pcap format)
- **CSV export** using Pandas for further analysis
- **Comprehensive logging** system

---

## 📋 Prerequisites

- **Kali Linux** (recommended)
- **Python 3.8+**
- **Root/sudo privileges** (required for packet capture)
- **tshark** (for PyShark support)

---

## 🔧 Full Installation (Kali Linux)

```bash
# 1. Create virtual environment with system packages access
python3 -m venv venv --system-site-packages

# 2. Activate environment
source venv/bin/activate

# 3. Install Python dependencies
pip install --upgrade pip
pip install -r requirements.txt

# 4. Install tshark (required for PyShark)
sudo apt install tshark -y
```

---

## 🤖 Train the ML Model on Real Traffic

**⚠️ REQUIRED for accurate anomaly detection**

### Step 1: Generate Normal Traffic (Victim VM)

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

### Step 2: Train the Model (Kali)

```bash
cd ~/network_ids
sudo venv/bin/python3 train_real_model.py

# → Wait ~30-60 seconds → [+] REAL MODEL TRAINED & SAVED
```

---

## 🎯 Launch the NIDS

```bash
cd ~/network_ids

# Make scripts executable
chmod +x run.sh demo_attacks.py

# Start the NIDS
./run.sh

# → Choose option 1 (Scapy only) → 100% stable, zero freeze
```

**Dashboard Access:** `http://YOUR_KALI_IP:5000`

---

## 💥 Attack Demo

**Make the dashboard explode in 30 seconds!**

In another terminal:

```bash
./demo_attacks.py 172.168.100.4     # ← Replace with your victim's VM IP
```

### Triggers:
- ✅ SYN / Xmas / Null / FIN scans
- ✅ ML-based anomalies
- ✅ SQLi / LFI simulation
- ✅ ICMP flood

---

## 🎨 Web Dashboard Features

- 📊 **Real-time threat counter**
- 🏷️ **Human-readable attack names**
  - Examples: "Xmas Scan (Stealth)", "SQLi / LFI Attempt"
- 🔌 **Target port + service name**
  - SSH, HTTP, SMB, RDP, MySQL, etc.
- 🎨 **Color-coded severity levels**
  - 🔴 Red / 🟠 Orange / 🟡 Yellow / 🟢 Green
- 💻 **Cyberpunk professional design**

---

## 📁 Project Structure & File Descriptions

```
network_ids/
├── main.py                  → Main entry point — starts capture + Flask server
├── capture_scapy.py         → Primary packet capture using Scapy (stable & recommended)
├── capture_pyshark.py       → PyShark capture (kept for requirement, disabled if unstable)
├── signatures.py            → 35+ rule-based detection engine (scans, exploits, web attacks)
├── anomalies.py             → ML anomaly detection using Isolation Forest (real traffic trained)
├── alerts.py                → Alert logging, terminal display, CSV export (Pandas)
├── utils.py                 → Feature extraction for ML model
├── train_real_model.py      → Manual training script on real lab traffic (REQUIRED)
├── run.sh                   → One-click launcher
├── demo_attacks.py          → Automatic attack demo script (30 seconds = dashboard explosion)
├── requirements.txt         → All Python dependencies
├── data/                    → Stores .pcap files, processed CSVs, and trained ML model
├── logs/                    → Full alert log with timestamps
├── web_ui/
│   ├── app.py               → Flask backend serving the dashboard
│   ├── templates/index.html → Beautiful real-time dashboard (colors, ports, icons)
│   └── static/style.css     → Cyberpunk theme
└── README.md                → This file
```

---

## 🛠️ Technologies Used

- **Scapy** - Packet manipulation and capture
- **PyShark** - Alternative packet capture interface
- **Scikit-learn** - Machine learning (Isolation Forest)
- **Flask** - Web dashboard backend
- **Pandas** - Data processing and CSV export
- **Python 3.8+** - Core programming language

---

## 📊 Detection Capabilities

### Signature-Based Detection (35+ Rules)
- Port scanning techniques (SYN, Xmas, Null, FIN)
- SQL Injection attempts
- Local File Inclusion (LFI)
- SMB exploitation
- ICMP flooding
- Suspicious traffic patterns

### ML-Based Anomaly Detection
- Trained on real network traffic
- Isolation Forest algorithm
- Detects unknown/zero-day attacks
- Adaptive learning from normal behavior

---

## 🎓 Academic Project

This project was developed as part of a university cybersecurity course, demonstrating:
- Network security fundamentals
- Machine learning applications in cybersecurity
- Real-time threat detection systems
- Full-stack development skills

---

## 📝 License

This project is for **academic purposes only**.

---

## 👤 Author

**Mohamed Taher BORGI**

*Cybersecurity Enthusiast | Network Security | Machine Learning*

---

<div align="center">

**⭐ If this project helps you, please star it! ⭐**

Made with ❤️ by me

</div>
