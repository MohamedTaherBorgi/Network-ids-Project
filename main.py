from capture_scapy import start_scapy_capture
from capture_pyshark import start_pyshark_capture
from web_ui.app import app
import threading
import os

print("""
╔═══════════════════════════════════════════════════════════════╗
║                     WELCOME TO NETWORK IDS                    ║
╚═══════════════════════════════════════════════════════════════╝
""")

choice = input("Start capture with:\n1) Scapy only (RECOMMENDED)\n2) PyShark only\n3) Both\n> ").strip()

os.makedirs("data/captures", exist_ok=True)
os.makedirs("logs", exist_ok=True)

if choice == "1":
    print("[+] Starting Scapy only")
    threading.Thread(target=start_scapy_capture, daemon=True).start()
elif choice == "2":
    print("[+] Starting PyShark only")
    threading.Thread(target=start_pyshark_capture, daemon=True).start()
elif choice == "3":
    print("[+] Starting BOTH (Scapy main + PyShark backup)")
    threading.Thread(target=start_scapy_capture, daemon=True).start()
    threading.Thread(target=start_pyshark_capture, daemon=True).start()
else:
    print("[+] Default: Scapy only")
    threading.Thread(target=start_scapy_capture, daemon=True).start()

def get_local_ip():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP

print(f"[+] Dashboard → http://{get_local_ip()}:5000")
app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
