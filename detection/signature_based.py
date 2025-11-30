"""
Signature-Based Detection Engine
Handles rule-based detection for known attack patterns
"""

from collections import defaultdict
from datetime import datetime, timedelta
import re


class SignatureDetector:
    """
    Signature-based intrusion detection engine.
    Includes:
        - Port scan detection
        - DDoS detection
        - ARP spoofing
        - SQL injection patterns
        - XSS injection patterns
        - Brute force detection (optional)
    """

    def __init__(self):
        # -------- Port Scan Tracking -------- #
        self.port_scan_threshold = 20
        self.port_scan_window = timedelta(seconds=60)
        self.port_connections = defaultdict(list)

        # -------- DDoS Tracking -------- #
        self.ddos_threshold = 100
        self.ddos_window = timedelta(seconds=10)
        self.packet_times = defaultdict(list)

        # -------- ARP Tracking -------- #
        self.arp_table = {}

        # -------- Brute Force Tracking -------- #
        self.bruteforce_threshold = 5
        self.bruteforce_window = timedelta(seconds=60)
        self.failed_logins = defaultdict(list)

        # -------- SQL Injection Patterns -------- #
        self.sqli_patterns = [
            r"union\s+select",
            r"or\s+1\s*=\s*1",
            r";\s*drop\s+table",
            r"'\s*or\s*'.*'\s*=\s*'",
            r"--",
            r"xp_cmdshell",
            r"exec\s*\(",
        ]

        # -------- XSS Patterns -------- #
        self.xss_patterns = [
            r"<script[^>]*>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
        ]

    # ----------------------------------------------------------------------- #
    # PORT SCAN DETECTION
    # ----------------------------------------------------------------------- #
    def detect_port_scan(self, pkt):
        if pkt.get("protocol") != "TCP":
            return None

        if 'S' not in str(pkt.get("flags", "")):
            return None

        src_ip = pkt["src_ip"]
        dst_port = pkt["dst_port"]
        now = datetime.now()

        self.port_connections[src_ip].append((dst_port, now))

        # clean old connections
        cutoff = now - self.port_scan_window
        self.port_connections[src_ip] = [
            (p, t) for p, t in self.port_connections[src_ip] if t > cutoff
        ]

        unique_ports = len({p for p, _ in self.port_connections[src_ip]})

        if unique_ports >= self.port_scan_threshold:
            return {
                "alert_type": "PORT_SCAN",
                "severity": "HIGH",
                "src_ip": src_ip,
                "dst_ip": pkt["dst_ip"],
                "ports_scanned": unique_ports,
                "detection_method": "signature",
                "message": f"Port scan detected ({unique_ports} unique ports)"
            }

        return None

    # ----------------------------------------------------------------------- #
    # DDoS DETECTION
    # ----------------------------------------------------------------------- #
    def detect_ddos(self, pkt):
        src_ip = pkt["src_ip"]
        now = datetime.now()

        self.packet_times[src_ip].append(now)

        # Remove packets outside window
        cutoff = now - self.ddos_window
        self.packet_times[src_ip] = [t for t in self.packet_times[src_ip] if t > cutoff]

        count = len(self.packet_times[src_ip])

        if count >= self.ddos_threshold:
            rate = count / self.ddos_window.seconds

            if rate > 500:
                sev = "CRITICAL"
            elif rate > 300:
                sev = "HIGH"
            else:
                sev = "MEDIUM"

            return {
                "alert_type": "DDOS",
                "severity": sev,
                "src_ip": src_ip,
                "dst_ip": pkt["dst_ip"],
                "packet_count": count,
                "packet_rate": f"{rate:.1f} pps",
                "detection_method": "signature",
                "message": "Potential DDoS attack detected"
            }

        return None

    # ----------------------------------------------------------------------- #
    # ARP SPOOFING
    # ----------------------------------------------------------------------- #
    def detect_arp_spoof(self, pkt):
        if pkt.get("protocol") != "ARP":
            return None

        src_ip = pkt["src_ip"]
        src_mac = pkt.get("src_mac")
        if not src_mac:
            return None

        if src_ip in self.arp_table and self.arp_table[src_ip] != src_mac:
            return {
                "alert_type": "ARP_SPOOF",
                "severity": "CRITICAL",
                "ip_address": src_ip,
                "original_mac": self.arp_table[src_ip],
                "spoofed_mac": src_mac,
                "detection_method": "signature",
                "message": f"ARP spoofing detected: {src_ip} MAC changed!"
            }

        self.arp_table[src_ip] = src_mac
        return None

    # ----------------------------------------------------------------------- #
    # SQL INJECTION DETECTION
    # ----------------------------------------------------------------------- #
    def detect_sql_injection(self, pkt):
        if pkt.get("dst_port") not in [80, 8080, 443]:
            return None

        payload = str(pkt.get("payload", "")).lower()

        for p in self.sqli_patterns:
            if re.search(p, payload, re.IGNORECASE):
                return {
                    "alert_type": "SQL_INJECTION",
                    "severity": "HIGH",
                    "src_ip": pkt["src_ip"],
                    "dst_ip": pkt["dst_ip"],
                    "pattern": p,
                    "detection_method": "signature",
                    "message": "SQL injection pattern detected"
                }

        return None

    # ----------------------------------------------------------------------- #
    # XSS DETECTION
    # ----------------------------------------------------------------------- #
    def detect_xss(self, pkt):
        if pkt.get("dst_port") not in [80, 8080, 443]:
            return None

        payload = str(pkt.get("payload", ""))

        for p in self.xss_patterns:
            if re.search(p, payload, re.IGNORECASE):
                return {
                    "alert_type": "XSS",
                    "severity": "MEDIUM",
                    "src_ip": pkt["src_ip"],
                    "dst_ip": pkt["dst_ip"],
                    "pattern": p,
                    "detection_method": "signature",
                    "message": "Cross-site scripting attempt detected"
                }

        return None

    # ----------------------------------------------------------------------- #
    # RUN ALL DETECTORS
    # ----------------------------------------------------------------------- #
    def detect_all(self, pkt):
        alerts = []

        detections = [
            self.detect_port_scan,
            self.detect_ddos,
            self.detect_arp_spoof,
            self.detect_sql_injection,
            self.detect_xss,
        ]

        for detector in detections:
            try:
                alert = detector(pkt)
                if alert:
                    alerts.append(alert)
            except Exception as e:
                print(f"[ERROR] {detector.__name__}: {e}")

        return alerts
