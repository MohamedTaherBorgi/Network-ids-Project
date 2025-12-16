#!/bin/bash
echo "[*] STARTING REALISTIC NORMAL TRAFFIC GENERATOR"
echo "[*] This will generate diverse traffic for NIDS training"
echo "[*] Press Ctrl+C to stop"

# 1. Fast external HTTP (different sites = different packet sizes)
while true; do
    curl -s -m 5 http://httpbin.org/get >/dev/null
    curl -s -m 5 http://httpbin.org/ip >/dev/null
    curl -s -m 5 http://httpbin.org/headers >/dev/null
    curl -s -m 5 http://httpbin.org/user-agent >/dev/null
    sleep 0.2
done &

# 2. HTTPS traffic (TLS handshake + data)
while true; do
    curl -s -m 5 https://example.com >/dev/null
    curl -s -m 5 https://www.google.com >/dev/null
    curl -s -m 5 https://httpbin.org/get >/dev/null
    sleep 0.3
done &

# 3. DNS queries (UDP port 53)
while true; do
    dig google.com >/dev/null 2>&1
    dig github.com >/dev/null 2>&1
    dig httpbin.org >/dev/null 2>&1
    sleep 0.4
done &

# 4. ICMP to Kali and external
KALI_IP="192.168.125.3"  # ← CHANGE TO YOUR KALI IP
while true; do
    ping -c 1 -W 1 $KALI_IP >/dev/null 2>&1
    ping -c 1 -W 1 8.8.8.8 >/dev/null 2>&1
    ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1
    sleep 0.5
done &

# 5. Optional: SSH handshake loop (if SSH server running on Ubuntu)
if command -v ssh >/dev/null 2>&1; then
    while true; do
        ssh -o StrictHostKeyChecking=no -o BatchMode=yes localhost whoami >/dev/null 2>&1
        sleep 4
    done &
fi

echo "[+] All 5 traffic generators running in background"
echo "[+] Go back to Kali and run: sudo venv/bin/python3 train_real_model.py"
echo "[+] Let it capture 1000+ packets → Ctrl+C when ready"
echo "[+] Press Ctrl+C here to stop all traffic"

# Wait for user to stop
trap "kill 0" SIGINT
wait
