# signatures.py
# Module containing signature-based detection rules for common network and web attacks
# These rules are kept simple and focused on high-impact threats to make them easy to understand and extend

from alerts import log_alert
from scapy.all import IP, TCP, ICMP
import time
from collections import defaultdict

# Global debounce dictionary to limit alert frequency per flow/port
# Prevents flooding the console/logs during sustained attacks (e.g., rapid port scans)
_last_alert = defaultdict(float)

def check_web_signatures(payload: str, src: str, dst: str):
    """
    Checks HTTP payloads for signs of common web application attacks.
    Focuses on SQL injection and local file inclusion patterns.
    Works on decoded payloads from ports 80/8080.
    """
    if not payload:
        return
   
    try:
        # Convert to lowercase for case-insensitive matching
        payload_lower = payload.lower()
       
        # Basic SQL injection patterns - covers common encoded and plain variants
        if any(p in payload_lower for p in ["%27+or+", "1%27+or", "or+%271%27%3d%271", "' or ", "1=1", "union select", "admin'--", "%27--"]):
            log_alert("[L7] SQL INJECTION DETECTED", src, dst)
       
        # Directory traversal / LFI patterns - looks for path climbing attempts
        if any(p in payload_lower for p in ["../", "..%2f", "/etc/passwd", "..%252f"]):
            log_alert("[L7] DIRECTORY TRAVERSAL DETECTED", src, dst)
   
    except Exception:
        # Silent fail if payload processing fails (rare encoding issues)
        pass

def check_network_signatures(pkt):
    """
    Network-layer signature checks for common scanning and flooding techniques.
    Examines TCP flags, destination ports, and ICMP types.
    Uses debounce to avoid duplicate alerts on the same flow.
    """
    if not pkt.haslayer(IP):
        return
   
    try:
        src = pkt[IP].src
        dst = pkt[IP].dst
        now = time.time()
       
        if pkt.haslayer(TCP):
            flags = int(pkt[TCP].flags)
            port = pkt[TCP].dport
            # Unique key per source-destination-port to track individual scan attempts
            key = f"{src}->{dst}-{port}"
           
            # Debounce: no more than one alert per 10 seconds for the same flow/port
            if now - _last_alert[key] < 10:
                return
           
            # SYN scan detection - SYN flag set without ACK (typical Nmap -sS behavior)
            # Only alerts on common service ports to reduce noise
            if flags & 0x02 and not flags & 0x10:
                if port in [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]:
                    log_alert(f"[NET] SYN Scan → port {port}", src, dst)
                    _last_alert[key] = now
           
            # Stealth scans (FIN, NULL, Xmas) - specific flag combinations used by Nmap
            if flags in [0x29, 0x00, 0x01]:
                log_alert(f"[NET] STEALTH SCAN detected", src, dst)
                _last_alert[key] = now
       
        # ICMP flood detection - focuses on echo requests (type 8)
        # Separate debounce with longer interval since floods are high-volume
        if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
            key = f"{src}->{dst}-icmp"
            if now - _last_alert[key] > 5:
                log_alert("[NET] ICMP Flood detected", src, dst)
                _last_alert[key] = now
   
    except Exception:
        # Broad exception handling to keep capture running even if one packet fails
        pass

def check_signatures_pyshark(packet):
    """
    Simplified signature checks specifically for PyShark-captured packets.
    Provides basic detection in the backup engine without full web payload analysis.
    Mirrors the main Scapy rules for SYN scans, stealth scans, and ICMP floods.
    """
    try:
        if not hasattr(packet, 'ip'):
            return
       
        src = packet.ip.src
        dst = packet.ip.dst
       
        if hasattr(packet, 'tcp'):
            # Flags are hexadecimal strings in PyShark, so convert to int
            flags = int(packet.tcp.flags, 16)
            
            # SYN scan - SYN flag without ACK
            if flags & 0x02 and not flags & 0x10:
                port = int(packet.tcp.dstport)
                if port in [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 8080]:
                    log_alert(f"[PYSHARK] SYN Scan → port {port}", src, dst)
           
            # Stealth scan patterns
            if flags in [0x29, 0x00, 0x01]:
                log_alert(f"[PYSHARK] STEALTH SCAN detected", src, dst)
       
        # ICMP echo request detection for flood alerts
        if packet.highest_layer == "ICMP" and packet.icmp.type == "8":
            log_alert("[PYSHARK] ICMP flood detected", src, dst)
   
    except Exception:
        # Silent handling to prevent capture interruption
        pass
