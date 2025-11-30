from detection.signature_based import SignatureDetector

detector = SignatureDetector()

# ---------------------- TEST PORT SCAN -----------------------
print("\n=== TEST: PORT SCAN ===")
for port in range(1, 25):  # 24 ports → above threshold 20
    pkt = {
        "protocol": "TCP",
        "src_ip": "192.168.1.10",
        "dst_ip": "192.168.1.5",
        "dst_port": port,
        "flags": "S"
    }
    alerts = detector.detect_all(pkt)
    if alerts:
        print(alerts)

# ---------------------- TEST DDoS ----------------------------
print("\n=== TEST: DDoS ===")
for i in range(120):  # >100 packets to trigger DDoS rule
    pkt = {
        "protocol": "TCP",
        "src_ip": "10.0.0.99",
        "dst_ip": "10.0.0.5",
        "dst_port": 80,
        "flags": ""
    }
    alerts = detector.detect_all(pkt)
    if alerts:
        print(alerts)

# ---------------------- TEST ARP SPOOF -----------------------
print("\n=== TEST: ARP SPOOF ===")
# First normal ARP packet
pkt1 = {
    "protocol": "ARP",
    "src_ip": "192.168.1.50",
    "src_mac": "AA:BB:CC:DD:EE:01"
}
detector.detect_all(pkt1)

# Now spoofed MAC
pkt2 = {
    "protocol": "ARP",
    "src_ip": "192.168.1.50",
    "src_mac": "AA:BB:CC:DD:EE:99"
}
print(detector.detect_all(pkt2))

# ---------------------- TEST SQL INJECTION -----------------------
print("\n=== TEST: SQL Injection ===")
pkt = {
    "protocol": "TCP",
    "src_ip": "1.2.3.4",
    "dst_ip": "5.6.7.8",
    "dst_port": 80,
    "payload": "id=1 OR 1=1; DROP TABLE users"
}
print(detector.detect_all(pkt))

# ---------------------- TEST XSS -----------------------
print("\n=== TEST: XSS ===")
pkt = {
    "protocol": "TCP",
    "src_ip": "9.9.9.9",
    "dst_ip": "8.8.8.8",
    "dst_port": 80,
    "payload": "<script>alert('hacked')</script>"
}
print(detector.detect_all(pkt))
