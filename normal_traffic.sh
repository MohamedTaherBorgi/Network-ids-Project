#!/bin/bash

echo "[*] STARTING REALISTIC NORMAL TRAFFIC GENERATOR"
echo "[*] Diverse + bidirectional traffic for accurate NIDS ML training"
echo "[*] Press Ctrl+C to stop all generators"

# CONFIG — CHANGE THESE TO YOUR ACTUAL IPs
UBUNTU_IP= <Victim>   # This machine (victim)
KALI_IP= <Kali>      # Kali IDS machine — CHANGE IF DIFFERENT

# 1. External HTTP variation
while true; do
    curl -s -m 5 http://httpbin.org/get >/dev/null
    curl -s -m 5 http://httpbin.org/ip >/dev/null
    curl -s -m 5 http://httpbin.org/headers >/dev/null
    curl -s -m 5 http://httpbin.org/user-agent >/dev/null
    sleep 0.15
done &

# 2. HTTPS with full TLS handshakes
while true; do
    curl -s -m 5 https://example.com >/dev/null
    curl -s -m 5 https://www.google.com >/dev/null
    curl -s -m 5 https://httpbin.org/get >/dev/null
    sleep 0.25
done &

# 3. DNS queries (UDP/53)
while true; do
    dig google.com >/dev/null 2>&1
    dig github.com >/dev/null 2>&1
    dig httpbin.org >/dev/null 2>&1
    sleep 0.3
done &

# 4. BIDIRECTIONAL LOCAL TRAFFIC — CRITICAL FOR ML ACCURACY
while true; do
    curl -s -m 3 http://$KALI_IP >/dev/null 2>&1      # Ubuntu → Kali HTTP attempt
    ping -c 1 -W 1 $KALI_IP >/dev/null 2>&1          # Ubuntu → Kali ICMP
    sleep 0.3
done &

# 5. External ICMP (for variety)
while true; do
    ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1
    ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1
    sleep 0.5
done &

# 6. Local SSH handshakes (if sshd running on this machine)
if command -v ssh >/dev/null 2>&1; then
    while true; do
        ssh -o StrictHostKeyChecking=no -o BatchMode=yes -o ConnectTimeout=3 localhost whoami >/dev/null 2>&1
        sleep 3
    done &
fi

echo "[+] All 6 traffic generators running in background"
echo "[+] Bidirectional local traffic included (no more false anomalies)"
echo "[+] Go to Kali → run: sudo venv/bin/python3 train_real_model.py"
echo "[+] Capture 1500+ packets → Ctrl+C → model saves"
echo "[+] Then Ctrl+C here to stop traffic"

trap "echo '[!] Stopping all generators...'; kill 0" SIGINT
wait
