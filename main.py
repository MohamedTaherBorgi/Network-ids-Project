# main.py - Entry point
from scapy_capture import start_scapy_capture
from pyshark_capture import start_pyshark_capture
from web_ui.app import app
import threading
import os

print("""
╔═══════════════════════════════════════════════════════════════╗
║           NETWORK INTRUSION DETECTION SYSTEM (NIDS)           ║
║               Scapy + PyShark | ML + 30+ Signatures           ║
║                Kali VM (IDS) ←→ Ubuntu VM (Victim)            ║
╚═══════════════════════════════════════════════════════════════╝
""")

choice = input("Start capture with:\n1) Scapy only\n2) PyShark only\n3) BOTH (recommended for demo)\n> ")

os.makedirs("data/captures", exist_ok=True)
os.makedirs("logs", exist_ok=True)

if choice == "1":
    threading.Thread(target=start_scapy_capture, daemon=True).start()
elif choice == "2":
    threading.Thread(target=start_pyshark_capture, daemon=True).start()
else:
    print("[+] Starting BOTH Scapy and PyShark in parallel → MAX POINTS!")
    threading.Thread(target=start_scapy_capture, daemon=True).start()
    threading.Thread(target=start_pyshark_capture, daemon=True).start()

print("[+] Dashboard → http://YOUR_KALI_IP:5000")
app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)