# utils.py — OPTIMIZED FEATURE EXTRACTION
import numpy as np
from scapy.all import IP, TCP, UDP

def extract_features_scapy(pkt):
    """
    Extract 5 features for ML anomaly detection:
    1. Packet length
    2. IP protocol
    3. Source port
    4. Destination port
    5. TCP flags (0 if not TCP)
    """
    if not pkt.haslayer(IP):
        return None
    
    ip = pkt[IP]
    
    src_port = 0
    dst_port = 0
    flags = 0
    
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = int(pkt[TCP].flags)
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
    
    return [
        len(pkt),       # Packet size — key for detecting floods/large payloads
        ip.proto,       # Protocol (6=TCP, 1=ICMP, 17=UDP)
        src_port,       # Source port (high = client, low = server)
        dst_port,       # Destination port (80, 22, etc.)
        flags           # TCP flags — critical for scan detection
    ]
