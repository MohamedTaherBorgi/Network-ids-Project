# utils.py
# Utility module for feature extraction from captured packets
# These features are specifically chosen for the Isolation Forest anomaly detection
# They provide a good balance between simplicity and effectiveness for detecting unusual traffic

import numpy as np
from scapy.all import IP, TCP, UDP

def extract_features_scapy(pkt):
    """
    Extracts a fixed set of 5 numerical features from each IP packet.
    These features are used to train the Isolation Forest model and for real-time anomaly detection.
    
    Chosen features:
    1. Packet length - helps spot oversized payloads or flood attempts
    2. IP protocol number - distinguishes TCP/UDP/ICMP traffic
    3. Source port - high ports typical for clients, low for servers
    4. Destination port - common ports indicate service targeting
    5. TCP flags value - critical for identifying scan types and connection states
    
    Returns None for non-IP packets to skip them during training/detection.
    """
    # Basic filter - only process packets with an IP layer
    if not pkt.haslayer(IP):
        return None
   
    ip = pkt[IP]
   
    # Default values for non-TCP/UDP packets
    src_port = 0
    dst_port = 0
    flags = 0
   
    # Handle TCP packets - most common for scans and web traffic
    if pkt.haslayer(TCP):
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
        flags = int(pkt[TCP].flags)  # Convert flags to integer for numerical processing
    
    # Handle UDP packets - important for DNS and some services
    elif pkt.haslayer(UDP):
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport
   
    # Return the feature vector as a list - easy to convert to numpy array later
    return [
        len(pkt),     # Total packet length in bytes
        ip.proto,     # Protocol number from IP header (6=TCP, 17=UDP, 1=ICMP, etc.)
        src_port,     # Source port number
        dst_port,     # Destination port number
        flags         # TCP flags as integer (0 for non-TCP packets)
    ]
