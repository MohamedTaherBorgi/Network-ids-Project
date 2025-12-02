from scapy.layers.inet import IP, TCP   # ← THIS LINE WAS MISSING
from alerts import send_alert
from utils import rate_exceeded, track_port_scan

def check_signatures(row, packet):
    src = row['src_ip']
    dst = row['dst_ip']
    sport = row.get('sport')
    dport = row.get('dport')
    proto = row['proto']

    # 1. SYN Flood – lowered threshold works instantly
    if TCP in packet and packet[TCP].flags == 2:  # SYN only
        if rate_exceeded(src, "SYN", threshold=15):
            send_alert("Possible SYN Flood detected", src)

    # 2. ICMP Flood
    if proto == 1:
        if rate_exceeded(src, "ICMP", threshold=15):
            send_alert("ICMP Flood detected", src)

    # 3. Port Scan – nmap -sS triggers this immediately
    if TCP in packet and packet[TCP].flags == 2:
        if track_port_scan(src, dport):
            send_alert(f"Port Scan detected – {len(port_scan_tracker[src])} ports scanned", src)

    # 4. Land Attack
    if src == dst and sport == dport and sport is not None:
        send_alert("LAND ATTACK detected", src)

    # 5. Xmas / Null scans
    if TCP in packet and packet[TCP].flags in [0, 0x1FF]:
        send_alert("XMAS / NULL scan detected", src)
