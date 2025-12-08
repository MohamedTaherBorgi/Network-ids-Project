from capture_scapy import start_scapy_capture
from capture_pyshark import start_pyshark_capture
from web_ui.app import app
import threading
import os

print("""
╔═══════════════════════════════════════════════════════════════╗
║                    WELCOME TO NETWORK IDS                     ║
╚═══════════════════════════════════════════════════════════════╝
""")

choice = input("Start capture with:\n1) Scapy only (RECOMMENDED — 100% stable)\n2) PyShark only\n3) Both (PyShark is disabled on this VM)\n> ").strip()

os.makedirs("data/captures", exist_ok=True)
os.makedirs("logs", exist_ok=True)

# Start capture based on choice
if choice == "1":
    print("[+] Starting Scapy only — PERFECT stability")
    threading.Thread(target=start_scapy_capture, daemon=True).start()

elif choice == "2":
    print("[+] Starting PyShark only (may not work on some VMs)")
    threading.Thread(target=start_pyshark_capture, daemon=True).start()

elif choice == "3":
    print("[+] Starting BOTH (Scapy = main, PyShark = silent backup)")
    threading.Thread(target=start_scapy_capture, daemon=True).start()
    threading.Thread(target=start_pyshark_capture, daemon=True).start()

else:
    print("[!] Invalid choice → defaulting to Scapy only (recommended)")
    threading.Thread(target=start_scapy_capture, daemon=True).start()

print("[+] Dashboard → http://127.0.0.1:5000")
app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)