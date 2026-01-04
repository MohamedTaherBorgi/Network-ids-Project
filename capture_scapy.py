# capture_scapy.py
# Main packet capture engine using Scapy
# This is the primary capture method - fast, low-level, and processes packets in real time
# It runs asynchronously so the main program (Flask dashboard) stays responsive

import warnings
warnings.filterwarnings("ignore")  # Suppress Scapy warnings that clutter output during long runs

from scapy.all import AsyncSniffer, IP, TCP, ICMP, Raw, wrpcap
from signatures import check_network_signatures, check_web_signatures
from anomalies import detect_anomaly_scapy
import os
from datetime import datetime

# Interface to sniff on - change this if your VM uses a different name (e.g., enp0s3, eth0)
INTERFACE = "eth1"

# Global list to temporarily hold captured packets before writing to disk
packets = []

def scapy_callback(pkt):
    """
    Callback function executed for every captured packet.
    Processes the packet in several steps:
    1. Basic network-level signature checks (scans, floods)
    2. Machine learning anomaly detection
    3. Web application attack detection on HTTP ports (decodes payload)
    4. Buffers packets and periodically saves them to .pcap files
    """
    try:
        # Quick filter - ignore non-IP packets to save CPU
        if not pkt.haslayer(IP):
            return
        
        # 1. Network signatures (SYN scans, ICMP floods, etc.)
        check_network_signatures(pkt)
        
        # 2. Anomaly detection using the trained Isolation Forest model
        detect_anomaly_scapy(pkt)
        
        # 3. Simple web attack detection (SQLi, LFI) - only on ports 80 and 8080
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport in [80, 8080]:
            try:
                # Decode HTTP payload, ignore decoding errors
                payload = pkt[Raw].load.decode('utf-8', errors='ignore')
                check_web_signatures(payload, pkt[IP].src, pkt[IP].dst)
            except:
                pass  # Silent fail if payload can't be decoded
        
        # 4. Save packets to disk in batches of 100 to reduce I/O overhead
        packets.append(pkt)
        if len(packets) % 100 == 0:
            os.makedirs("data/captures", exist_ok=True)
            # Append the last 100 packets to a timestamped .pcap file (Wireshark compatible)
            wrpcap(f"data/captures/capture_{datetime.now().strftime('%H%M%S')}.pcap", packets[-100:], append=True)
    
    except Exception:
        # Broad exception catch to prevent one bad packet from crashing the entire capture thread
        pass

def start_scapy_capture():
    """
    Starts the asynchronous Scapy sniffer.
    Uses AsyncSniffer so capture runs in background thread and doesn't block Flask.
    Filter focuses on relevant protocols to reduce load.
    """
    print(f"[SCAPY] Starting capture on {INTERFACE}...")
    
    sniffer = AsyncSniffer(
        iface=INTERFACE,          # Interface in promiscuous mode
        prn=scapy_callback,       # Callback for each packet
        store=False,              # Don't store all packets in memory
        filter="tcp or icmp or udp",  # Only capture relevant traffic
        promisc=True,             # Capture all traffic on the network segment
        quiet=True                # Suppress Scapy's per-packet output
    )
    sniffer.start()               # Launch in background thread
    print("[SCAPY] Capture active — ready for attacks!")
