#!/usr/bin/env python3
from scapy.all import *
import pandas as pd
import datetime
import os
from signatures import check_signatures

# ────────────────────── CONFIG ──────────────────────
IFACE = "eth2"  # ← change only if needed

# Auto-create folders
os.makedirs("data/captures", exist_ok=True)
os.makedirs("data/processed", exist_ok=True)

# Global packet buffer + CSV writer
packet_buffer = []
csv_filename = f"data/processed/packets_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
pcap_filename = f"data/captures/capture_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng"

# Open pcap writer (Scapy's RawPcapNgWriter – no linktype needed, auto-detected)
pcap_writer = RawPcapNgWriter(pcap_filename)  # ← FIXED: no 'linktype' kwarg

def extract_features(packet):
    if IP not in packet:
        return None

    row = {
        'timestamp': datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f"),
        'src_ip': packet[IP].src,
        'dst_ip': packet[IP].dst,
        'proto': packet[IP].proto,
        'length': len(packet),
        'ttl': packet[IP].ttl,
        'sport': packet.sport if (TCP in packet or UDP in packet) else None,
        'dport': packet.dport if (TCP in packet or UDP in packet) else None,
        'tcp_flags': str(packet[TCP].flags) if TCP in packet else None,
        'payload_hex': packet.load.hex() if packet.load else None,
    }
    return row

def process_packet(packet):
    # Save raw packet to .pcapng
    pcap_writer.write(packet)

    row = extract_features(packet)
    if row:
        packet_buffer.append(row)
        check_signatures(row, packet)

    # Flush to CSV every 500 packets (or on Ctrl+C)
    if len(packet_buffer) >= 500:
        df = pd.DataFrame(packet_buffer)
        df.to_csv(csv_filename, mode='a', header=not os.path.exists(csv_filename), index=False)
        packet_buffer.clear()

# Graceful shutdown
def shutdown():
    print("\n[!] Saving remaining packets and closing files...")
    if packet_buffer:
        df = pd.DataFrame(packet_buffer)
        df.to_csv(csv_filename, mode='a', header=not os.path.exists(csv_filename), index=False)
        packet_buffer.clear()
    pcap_writer.close()
    print(f"[+] PCAP saved → {pcap_filename}")
    print(f"[+] CSV saved  → {csv_filename}")
    exit(0)

print(f"[+] Saving PCAP → {pcap_filename}")
print(f"[+] Saving CSV  → {csv_filename}")
print(f"[*] Starting capture on {IFACE} – Press Ctrl+C to stop")

try:
    sniff(iface=IFACE, prn=process_packet, store=False)
except KeyboardInterrupt:
    shutdown()
