# capture_scapy.py — SIMPLE & EASY TO EXPLAIN
import warnings
warnings.filterwarnings("ignore")

from scapy.all import AsyncSniffer, IP, TCP, ICMP, Raw, wrpcap
from signatures import check_network_signatures, check_web_signatures
from anomalies import detect_anomaly_scapy
import os
from datetime import datetime

INTERFACE = "eth1"
packets = []

def scapy_callback(pkt):
    try:
        if not pkt.haslayer(IP):
            return

        # 1. Network signatures
        check_network_signatures(pkt)

        # 2. Anomaly detection
        detect_anomaly_scapy(pkt)

        # 3. Simple web attack detection (Raw layer only)
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport in [80, 8080]:
            try:
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                check_web_signatures(payload, pkt[IP].src, pkt[IP].dst)
            except:
                pass

        # 4. Save packets
        packets.append(pkt)
        if len(packets) % 100 == 0:
            os.makedirs("data/captures", exist_ok=True)
            wrpcap(f"data/captures/capture_{datetime.now().strftime('%H%M%S')}.pcap", packets[-100:], append=True)

    except Exception:
        pass

def start_scapy_capture():
    print(f"[SCAPY] Starting capture on {INTERFACE}...")
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        prn=scapy_callback,
        store=False,
        filter="tcp or icmp or udp",
        promisc=True,
        quiet=True
    )
    sniffer.start()
    print("[SCAPY] Capture active — ready for attacks!")
