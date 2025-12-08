# signatures.py — FINAL: DETECTS SYN, XMAS, NULL, FIN, etc.
from alerts import log_alert # type: ignore
from scapy.all import IP, TCP, ICMP, Raw # type: ignore

def check_signatures_scapy(pkt):
    if not pkt.haslayer(IP):
        return

    try:
        src = pkt[IP].src
        dst = pkt[IP].dst

        if pkt.haslayer(TCP):
            flags = pkt[TCP].flags
            flag_int = int(flags) if hasattr(flags, '__int__') else flags

            # SYN Scan
            if flag_int & 0x02 and not flag_int & 0x10:  # SYN only
                port = pkt[TCP].dport
                if port in [21,22,23,25,80,443,445,1433,3306,3389,8080]:
                    log_alert(f"[SCAPY] SYN Scan → port {port}", src, dst)

            # Xmas, Null, FIN scans
            if flag_int in [0x29, 0x00, 0x01, 0x21, 0x08, 0x28]:
                log_alert(f"[SCAPY] STEALTH SCAN (flags: 0x{flag_int:02x})", src, dst)

        # ICMP flood
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            log_alert("[SCAPY] ICMP Echo Request → possible flood", src, dst)

        # Web attacks
        if pkt.haslayer(Raw) and pkt.haslayer(TCP) and pkt[TCP].dport in [80, 8080]:
            try:
                payload = pkt[Raw].load.decode(errors='ignore')
                if any(x in payload.upper() for x in ["UNION SELECT", "1=1", "OR 1=1", "../", "ETC/PASSWD"]):
                    log_alert("[SCAPY] Web attack (SQLi/LFI)", src, dst)
            except:
                pass

    except Exception:
        pass  # Never crash