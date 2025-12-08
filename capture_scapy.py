import warnings
warnings.filterwarnings("ignore")

from scapy.all import AsyncSniffer, IP, TCP, Raw, wrpcap # type: ignore
from signatures import check_signatures_scapy # type: ignore
from anomalies import detect_anomaly_scapy # type: ignore
import os
from datetime import datetime

INTERFACE = "eth2" # Interface

packets = []

def scapy_callback(pkt):
    try:
        if not pkt.haslayer(IP):
            return

        # Store packets
        packets.append(pkt)
        if len(packets) % 100 == 0:
            os.makedirs("data/captures", exist_ok=True)
            wrpcap(f"data/captures/scapy_{datetime.now().strftime('%H%M%S')}.pcap", packets[-100:], append=True)

        check_signatures_scapy(pkt)
        detect_anomaly_scapy(pkt)

    except Exception:
        pass

def start_scapy_capture():
    print(f"[SCAPY] Starting live capture on {INTERFACE}...")
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        prn=scapy_callback,
        store=False,
        filter="ip",
        quiet=True
    )
    sniffer.start()
    print("[SCAPY] Capture active — ready for attacks!")