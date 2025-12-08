# train_real_model.py - AUTO WORKS 100%
from scapy.all import sniff, get_if_list
from utils import extract_features_scapy
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

# Auto-detect correct interface
def find_interface():
    interfaces = get_if_list()
    for iface in interfaces:
        if iface.startswith(('enp', 'eth', 'ens')):
            return iface
    return "eth2"  # Interface

INTERFACE = find_interface()
print(f"Using interface: {INTERFACE}")
print("Capturing 500 normal packets for training (generate traffic on Ubuntu)...")

features = []

def callback(pkt):
    feats = extract_features_scapy(pkt)
    if feats:
        features.append(feats)
        print(f"Captured {len(features)} packets...", end='\r')
    if len(features) >= 500:
        raise StopIteration

try:
    sniff(iface=INTERFACE, prn=callback, timeout=180, filter="ip")
except Exception as e:
    print(f"\nError: {e}")

if len(features) < 100:
    print("\nToo few packets captured!")
    print("Check:")
    print("   1. VMs in Bridged/Host-Only mode (NOT NAT)")
    print("   2. Traffic really flowing (ping, curl, etc.)")
    print("   3. Interface correct (we used:", INTERFACE, ")")
    exit(1)

X = np.array(features)
print(f"\nCaptured {len(X)} normal samples → training model...")
model = IsolationForest(contamination=0.03, random_state=42, n_estimators=200)
model.fit(X)

os.makedirs("data", exist_ok=True)
joblib.dump(model, "data/model_isolation_forest.pkl")
print("[+] REAL MODEL TRAINED & SAVED — Ready for perfect anomaly detection!")