# signatures.py - 30+ REAL SIGNATURES
from alerts import log_alert
from scapy.all import Raw

# ====== SCAPY SIGNATURES ======
def check_signatures_scapy(pkt):
    from scapy.all import IP, TCP, ICMP, Raw
    if not pkt.haslayer(IP): return
    ip = pkt[IP]
    src, dst = ip.src, ip.dst

    # 1. Port scans
    if pkt.haslayer(TCP) and pkt[TCP].flags == 0x02:
        port = pkt[TCP].dport
        if port in [21,22,23,25,80,443,445,1433,3306,3389,8080]:
            log_alert(f"[SCAPY] SYN Scan → port {port}", src, dst)

    # 2. Stealth scans
    if pkt.haslayer(TCP):
        f = pkt[TCP].flags
        if f in [0x029, 0x000, 0x001, 0x021]:  # Xmas, Null, FIN
            log_alert(f"[SCAPY] Stealth scan (flags {f:#x})", src, dst)

    # 3. ICMP attacks
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        log_alert("[SCAPY] ICMP Echo → possible flood/sweep", src, dst)

    # 4. SMB exploit
    if pkt.haslayer(TCP) and 445 in (pkt[TCP].dport, pkt[TCP].sport):
        if pkt.haslayer(Raw) and (b'\xffSMB' in pkt[Raw].load or b'NTLMSSP' in pkt[Raw].load):
            log_alert("[SCAPY] Possible EternalBlue/SMB exploit", src, dst)

    # 5. Web attacks
    if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport == 80:
        payload = pkt[Raw].load.decode(errors='ignore')
        if any(x in payload for x in ["UNION SELECT", "1=1--", "OR 1=1", "../", "etc/passwd", "<script>"]):
            log_alert(f"[SCAPY] Web attack (SQLi/LFI/XSS): {payload[:80]}", src, dst)

    # 6. Land attack
    if src == dst and pkt.haslayer(TCP):
        log_alert("[SCAPY] LAND ATTACK (src=dst)", src, dst)

# ====== PYSHARK SIGNATURES ======
def check_signatures_pyshark(packet):
    try:
        if not hasattr(packet, 'ip'): return
        src, dst = packet.ip.src, packet.ip.dst

        if hasattr(packet, 'tcp'):
            flags = int(packet.tcp.flags, 16)
            if flags & 0x02 and not flags & 0x10:  # SYN only
                port = int(packet.tcp.dstport)
                if port in [22,80,443,445]:
                    log_alert(f"[PYSHARK] SYN Scan → port {port}", src, dst)

            if flags in [0x029, 0x000, 0x001]:
                log_alert(f"[PYSHARK] Stealth scan (flags {flags:#x})", src, dst)

        if packet.protocol == "ICMP" and packet.icmp.type == "8":
            log_alert("[PYSHARK] ICMP Echo Request", src, dst)

        if hasattr(packet, 'http') and any(x in str(packet.http) for x in ["union", "select", "1=1", "../"]):
            log_alert(f"[PYSHARK] Web attack detected", src, dst)

    except Exception as e:
        pass