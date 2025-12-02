#!/usr/bin/env python3
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import conf
conf.L3socket = conf.L2listen

import os
os.makedirs("data/captures", exist_ok=True)
os.makedirs("data/processed", exist_ok=True)
os.makedirs("logs", exist_ok=True)

print("""
╔══════════════════════════════════════════╗
║        Network IDS – FULL LOGGING        ║
║   Real-time .pcapng + CSV + Alerts       ║
╚══════════════════════════════════════════╝
""")

from capture import IFACE

print(f"[*] Interface : {IFACE}")
print(f"[*] PCAPs     → data/captures/")
print(f"[*] CSVs      → data/processed/")
print(f"[*] Logs      → logs/alerts.log")
print("[*] Press Ctrl+C to save & stop\n")

# This starts everything (capture.py handles the rest)
from capture import sniff, process_packet
sniff(iface=IFACE, prn=process_packet, store=False)
