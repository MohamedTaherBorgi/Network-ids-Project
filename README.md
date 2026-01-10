<div align="center">

# 🛡️ Network Intrusion Detection System (NIDS)

### University Cybersecurity Project — 2025

**Author:** Mohamed Taher BORGI

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Scapy](https://img.shields.io/badge/Scapy-Latest-green.svg)
![PyShark](https://img.shields.io/badge/PyShark-Latest-orange.svg)
![scikit-learn](https://img.shields.io/badge/scikit--learn-Latest-red.svg)
![Flask](https://img.shields.io/badge/Flask-Latest-black.svg)
![Status](https://img.shields.io/badge/Status-Active-success.svg)

</div>

---

## 🚀 Project Overview

<div align="center">

A real-time **Network Intrusion Detection System** built in Python that combines **signature-based detection** and **machine learning anomaly detection**.

The system monitors network traffic on a Kali Linux machine, detects common attacks (port scans, stealth scans, ICMP floods, SQL Injection, LFI), generates alerts, and displays them on a Flask dashboard.

</div>

### Key Highlights:

- Dual capture engines: **Scapy** (main, stable) + **PyShark** (backup)
- Signature detection for network and web attacks
- Anomaly detection using **Isolation Forest** trained on real traffic
- Full alert history with color-coded severity and custom colors for SQLi/LFI
- Automatic .pcap storage and CSV export

---

## 📋 Features

<div align="center">

| Feature | Description |
|---------|-------------|
| **Real-time Capture** | Scapy (primary) and PyShark (backup) |
| **Signature Detection** | SYN, Xmas, Null, FIN scans • ICMP floods • SQL Injection • LFI/Directory Traversal |
| **ML Anomaly Detection** | Isolation Forest with debouncing |
| **Professional Dashboard** | Real-time threat counter • Full alert history • Custom colors • Flash animations |
| **Alert Management** | Colored terminal output • Logging to `logs/alerts.log` • CSV export via Pandas |
| **Packet Storage** | Automatic .pcap format storage |

</div>

### Signature-based detection:
- SYN, Xmas, Null, FIN scans
- ICMP floods
- SQL Injection and LFI/Directory Traversal (deep HTTP inspection)

### Flask Dashboard Features:
- Real-time threat counter
- Full alert history (no deletion of old alerts)
- Custom colors: SQLi (blue), LFI (silver/gray), Anomaly (red), etc.
- New alerts flash animation

---

## 🔧 Prerequisites

<div align="center">

| Requirement | Description |
|-------------|-------------|
| **OS** | Kali Linux (recommended) |
| **Python** | 3.11+ |
| **VMs** | Two VMs: Kali (NIDS) + Ubuntu (Victim) |
| **Privileges** | Root privileges for packet capture |
| **Web Server** | Apache running on victim for web attack testing |

</div>

---

## 📦 Installation

```bash
# Clone the project
git clone https://github.com/MohamedTaherBorgi/Network-ids-Project.git
cd Network-ids-Project

# Create virtual environment
python3 -m venv venv --system-site-packages

# Activate
source venv/bin/activate

# Install dependencies
pip install --upgrade pip
pip install -r requirements.txt

# Install tshark for PyShark
sudo apt install tshark -y
```

---

## 🤖 Train the ML Model

<div align="center">

### ⚠️ REQUIRED for good anomaly detection

</div>

**Step 1:** Generate normal traffic on the victim VM (Ubuntu):
```bash
chmod +x normal_traffic.sh
./normal_traffic.sh
```

**Step 2:** Train the model on Kali:
```bash
sudo venv/bin/python3 train_real_model.py
# Wait for 1000+ packets → model saved with scaler
```

---

## 🎯 Launch the NIDS

```bash
./run.sh
# Choose:
# 1) Scapy only (recommended)
# 2) PyShark only
# 3) Both
```

<div align="center">

**Dashboard:** `http://<KALI_IP>:5000`

<img width="1918" height="743" alt="image" src="https://github.com/user-attachments/assets/234febcd-c8bd-4824-a018-35c249b96fde" />

</div>

---

## 💥 Demo Attacks

```bash
python3 demo_attacks.py <victim IP>
```

### Triggers:
- SYN / Xmas scans
- Aggressive scanning
- ICMP flood
- SQL Injection (with Apache on victim)
- Directory Traversal / LFI

### Manual web tests:
```bash
# SQLi (blue alert)
curl -s -G --data-urlencode "id=1' OR '1'='1" http://<victim IP>/

# LFI (silver/gray alert)
curl -s -G --data-urlencode "file=../../../../etc/passwd" http://<victim IP>/
```

---

## 🎨 Dashboard Highlights

<div align="center">

### Alert Severity Colors

| Attack Type | Color |
|-------------|-------|
| **SQL INJECTION** | 🔵 Blue |
| **LFI / Directory Traversal** | ⚪ Silver/Gray |
| **ANOMALY** | 🔴 Red |
| **Stealth Scans** | 🟠 Orange |
| **SYN Scans** | 🟡 Yellow |
| **ICMP** | 🟢 Green |

</div>

### Features:
- Full alert history (scrollable)
- New alerts flash
- Real-time counter

---

## 📁 Project Structure

```text
Network-ids-Project/
├── main.py                  → Launcher + engine selection
├── capture_scapy.py         → Main capture engine
├── capture_pyshark.py       → Backup capture engine
├── signatures.py            → Signature rules (network + web)
├── anomalies.py             → ML anomaly detection (debounced)
├── alerts.py                → Alert logging, terminal, CSV
├── utils.py                 → Feature extraction
├── train_real_model.py      → Real traffic training
├── test/
│   └── demo_attacks.py          → Automated attack demo
├── run.sh                   → One-click launcher
├── normal_traffic.sh        → Normal traffic generator for victim
├── requirements.txt
├── data/                    → .pcap, model, CSV
├── logs/                    → alerts.log
├── web_ui/
│   ├── app.py               → Flask server
│   ├── static/style.css     → Cyberpunk theme
│   └── templates/index.html → Dashboard
└── README.md
```

---

## 🛠️ Technologies Used

<div align="center">

| Technology | Purpose |
|------------|---------|
| **Scapy** | Primary packet capture & crafting |
| **PyShark** | Backup capture engine |
| **scikit-learn** | Isolation Forest anomaly detection |
| **Flask** | Real-time dashboard |
| **Pandas** | CSV export |
| **requests** | Clean HTTP attacks in demo |

</div>

---

## 🎓 Academic Value

This project demonstrates:

- Real-time network traffic analysis  
- Signature-based and ML-based intrusion detection  
- Deep packet inspection for web attacks  
- Alert management and visualization  
- Use of multiple tools (Scapy + PyShark) as required  

---

## 👤 Author

<div align="center">

**Mohamed Taher BORGI**

*Cybersecurity Student | Red Team Enthusiast | Network Security*

---

Made with ❤️ and packets

⭐ **Star this repo if it helped you!** ⭐

</div>
