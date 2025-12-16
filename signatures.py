# signatures.py — SIMPLE & CLEAR
from alerts import log_alert
from scapy.all import IP, TCP, ICMP
import time
from collections import defaultdict

_last_alert = defaultdict(float)

def check_web_signatures(payload: str, src: str, dst: str):
    if not payload:
        return
    
    try:
        payload_lower = payload.lower()
        
        # Simple SQLi patterns (encoded + decoded)
        if any(p in payload_lower for p in ["%27+or+", "1%27+or", "or+%271%27%3d%271", "' or ", "1=1", "union select", "admin'--", "%27--"]):
            log_alert("[L7] SQL INJECTION DETECTED", src, dst)
        
        # Simple LFI
        if any(p in payload_lower for p in ["../", "..%2f", "/etc/passwd", "..%252f"]):
            log_alert("[L7] DIRECTORY TRAVERSAL DETECTED", src, dst)
    
    except Exception:
        pass

def check_network_signatures(pkt):
    if not pkt.haslayer(IP):
        return
    
    try:
        src = pkt[IP].src
        dst = pkt[IP].dst
        now = time.time()
        
        if pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags)
            port = pkt[TCP].dport
            key = f"{src}->{dst}-{port}"
            
            if now - _last_alert[key] < 10:
                return
            
            # SYN Scan
            if flags & 0x02 and not flags & 0x10:
                if port in [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]:
                    log_alert(f"[NET] SYN Scan → port {port}", src, dst)
                    _last_alert[key] = now
            
            # Stealth
            if flags in [0x29, 0x00, 0x01]:
                log_alert(f"[NET] STEALTH SCAN detected", src, dst)
                _last_alert[key] = now
        
        # ICMP
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            key = f"{src}->{dst}-icmp"
            if now - _last_alert[key] > 5:
                log_alert("[NET] ICMP Flood detected", src, dst)
                _last_alert[key] = now
    
    except Exception:
        pass
def check_signatures_pyshark(packet):
    """Simple backup signatures for PyShark"""
    try:
        if not hasattr(packet, 'ip'):
            return
        
        src = packet.ip.src
        dst = packet.ip.dst
        
        if hasattr(packet, 'tcp'):
            flags = int(packet.tcp.flags, 16)
            if flags & 0x02 and not flags & 0x10:  # SYN only
                port = int(packet.tcp.dstport)
                if port in [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]:
                    log_alert(f"[PYSHARK] SYN Scan → port {port}", src, dst)
            
            if flags in [0x29, 0x00, 0x01]:
                log_alert(f"[PYSHARK] STEALTH SCAN detected", src, dst)
        
        if packet.highest_layer == "ICMP" and packet.icmp.type == "8":
            log_alert("[PYSHARK] ICMP flood detected", src, dst)
    
    except Exception:
        pass
