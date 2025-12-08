# utils.py
import numpy as np
from scapy.all import IP, TCP, UDP

def extract_features_scapy(pkt):
    if not pkt.haslayer(IP):
        return None
    ip = pkt[IP]
    return [
        len(pkt),
        ip.proto,
        pkt[TCP].sport if pkt.haslayer(TCP) else (pkt[UDP].sport if pkt.haslayer(UDP) else 0),
        pkt[TCP].dport if pkt.haslayer(TCP) else (pkt[UDP].dport if pkt.haslayer(UDP) else 0),
        int(pkt[TCP].flags) if pkt.haslayer(TCP) else 0
    ]
