k# 🛡️ Network Intrusion Detection System (NIDS)

### University Cybersecurity Project — 2025

<div align="center">

**Author:** Mohamed Taher BORGI  

[![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)](https://www.python.org/)
[![Scapy](https://img.shields.io/badge/Scapy-Packet%20Crafting-red.svg)](https://scapy.net/)
[![PyShark](https://img.shields.io/badge/PyShark-tshark%20Wrapper-lightgrey.svg)](https://kiminewt.github.io/pyshark/)
[![scikit-learn](https://img.shields.io/badge/scikit--learn-ML%20Anomaly-orange.svg)](https://scikit-learn.org/)
[![Flask](https://img.shields.io/badge/Flask-Web%20Dashboard-green.svg)](https://flask.palletsprojects.com/)
[![Status](https://img.shields.io/badge/Project%20Status-Completed-success.svg)]()

</div>

---

## 🚀 Project Overview

A **real-time Network Intrusion Detection System (NIDS)** built in Python that combines **signature-based detection** with **machine learning anomaly detection**.

The system monitors live network traffic on a Kali Linux machine, detects common network and web-based attacks, generates structured alerts, and visualizes them on a **professional cyberpunk-style Flask dashboard**.

### 🔑 Key Highlights

- Dual capture engines: **Scapy** (primary & stable) and **PyShark** (backup)
- Signature detection for **network scans** and **web attacks**
- ML-based anomaly detection using **Isolation Forest**
- Persistent alert history with **color-coded severity**
- Automatic **PCAP storage** and **CSV export**
- Real-time dashboard with animations and counters

---

## 📋 Features

### 🔍 Detection Capabilities

- **Signature-Based Detection**
  - SYN Scan
  - Xmas Scan
  - Null Scan
  - FIN Scan
  - ICMP Floods
  - SQL Injection (SQLi)
  - Local File Inclusion (LFI) / Directory Traversal

- **Machine Learning Anomaly Detection**
  - Isolation Forest trained on **real network traffic**
  - Feature scaling and debounced alerts to reduce noise

### 🖥️ Dashboard Features

- Real-time threat counter
- Scrollable **full alert history** (no deletion)
- Custom alert colors:
  - SQL Injection → Blue
  - LFI / Directory Traversal → Silver / Gray
  - Anomaly → Red
  - Stealth Scans → Orange
  - SYN Scan → Yellow
  - ICMP → Green
- Flash animation for new alerts

### 🧾 Alert Management

- Colored terminal output
- Logging to `logs/alerts.log`
- CSV export using Pandas
- PCAP packet storage for forensic analysis

---

## 🔧 Prerequisites

- Kali Linux (recommended)
- Python **3.11+**
- Two virtual machines:
  - Kali Linux (NIDS)
  - Ubuntu (Victim)
- Root privileges (packet capture)
- Apache running on victim VM (for web attack testing)

---

## 📦 Installation

```bash
git clone <your-repo>
cd Network-ids-Project

python3 -m venv venv --system-site-packages
source venv/bin/activate

pip install --upgrade pip
pip install -r requirements.txt

sudo apt install tshark -y
```

---

## 🤖 Train the Machine Learning Model

```bash
chmod +x normal_traffic.sh
./normal_traffic.sh
```

```bash
sudo venv/bin/python3 train_real_model.py
```

---

## 🎯 Launch the NIDS

```bash
./run.sh
```

Dashboard:
```
http://<KALI_IP>:5000
```

---

## 💥 Demo Attacks

```bash
python3 demo_attacks.py <VICTIM_IP>
```

Manual tests:

```bash
curl -s -G --data-urlencode "id=1' OR '1'='1" http://<VICTIM_IP>/
curl -s -G --data-urlencode "file=../../../../etc/passwd" http://<VICTIM_IP>/
```

---

## 📁 Project Structure

```text
Network-ids-Project/
├── main.py
├── capture_scapy.py
├── capture_pyshark.py
├── signatures.py
├── anomalies.py
├── alerts.py
├── utils.py
├── train_real_model.py
├── demo_attacks.py
├── run.sh
├── requirements.txt
├── data/
├── logs/
├── web_ui/
│   ├── app.py
│   └── templates/index.html
└── README.md
```

---

## 👤 Author

**Mohamed Taher BORGI**  
Cybersecurity Student | Red Team Enthusiast | Network Security  

⭐ Star this repository if it helped you ⭐

