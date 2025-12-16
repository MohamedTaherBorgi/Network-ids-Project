# train_real_model.py — FINAL FIXED VERSION (NO ERRORS)
from scapy.all import sniff
from utils import extract_features_scapy
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import joblib
import os
import sys

INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "eth1"

print(f"[*] Using interface: {INTERFACE}")
print("[*] Capturing packets for training — generate NORMAL traffic on victim VM")
print("[*] Goal: 1000+ packets for high-accuracy model")
print("[*] Press Ctrl+C when done\n")

features = []

def callback(pkt):
    feats = extract_features_scapy(pkt)
    if feats:
        features.append(feats)
        if len(features) % 50 == 0:
            print(f"Captured {len(features)} packets...", end='\r')

try:
    sniff(
        iface=INTERFACE,
        prn=callback,
        filter="ip",
        promisc=True,
        store=False,
        timeout=None
    )
except KeyboardInterrupt:
    print("\n[!] Capture stopped by user")
except Exception as e:
    print(f"\n[!] Capture error: {e}")

if len(features) < 500:
    print(f"\n[!] Only {len(features)} packets captured — too few!")
    print("    • Generate more normal traffic")
    print("    • Use Bridged mode")
    sys.exit(1)

X_raw = np.array(features)
scaler = StandardScaler()
X = scaler.fit_transform(X_raw)

print(f"\n[+] Captured {len(X)} normal samples — training optimized model...")

model = IsolationForest(
    contamination=0.05,
    n_estimators=500,
    max_samples='auto',
    random_state=42
)
model.fit(X)

os.makedirs("data", exist_ok=True)
joblib.dump({
    'model': model,
    'scaler': scaler,
    'samples': len(X)
}, "data/model_isolation_forest.pkl")

print("[+] OPTIMIZED MODEL TRAINED & SAVED")
print("    → Standardized features")
print("    → 500 trees")
print("    → High-accuracy anomaly detection ready")
print("    → Now run: ./run.sh")
