# main.py
from capture_scapy import start_scapy_capture # type: ignore
from capture_pyshark import start_pyshark_capture # type: ignore
from web_ui.app import app # type: ignore
import threading
import os

print("""
╔═══════════════════════════════════════════════════════════════╗
║                     WELCOME TO NETWORK IDS                    ║
╚═══════════════════════════════════════════════════════════════╝
""")

choice = input("Start capture with:\n1) Scapy only (RECOMMENDED)\n2) PyShark only\n3) Both\n> ")

os.makedirs("data/captures", exist_ok=True)
os.makedirs("logs", exist_ok=True)

if choice == "1":
    threading.Thread(target=start_scapy_capture, daemon=True).start()
else:
    print("[+] Starting capture...")
    threading.Thread(target=start_scapy_capture, daemon=True).start()
    if choice == "3":
        threading.Thread(target=start_pyshark_capture, daemon=True).start()

print("[+] Dashboard → http://127.0.0.1:5000")
app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)