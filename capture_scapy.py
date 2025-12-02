# scapy_capture.py
from scapy.all import AsyncSniffer, IP, TCP, ICMP, Raw
from signatures import check_signatures_scapy
from anomalies import detect_anomaly_scapy
import os
from datetime import datetime

INTERFACE = "eth0"  # Change if needed: enp0s3, eth0, etc.

def scapy_callback(pkt):
    if pkt.haslayer(IP):
        check_signatures_scapy(pkt)
        detect_anomaly_scapy(pkt)

def start_scapy_capture():
    print(f"[SCAPY] Starting live capture on {INTERFACE}...")
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        prn=scapy_callback,
        store=False,
        filter="ip"
    )
    sniffer.start()
    print("[SCAPY] Capture active")