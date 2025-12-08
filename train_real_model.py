from scapy.all import sniff, get_if_list # type: ignore
from utils import extract_features_scapy
import numpy as np # type: ignore
from sklearn.ensemble import IsolationForest # type: ignore
import joblib # type: ignore
import os

INTERFACE = "eth2" # Interface
print(f"Using interface: {INTERFACE}")
print("Capturing 500 normal packets for training (generate traffic on victims VM)...")

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
print("[+] REAL MODEL TRAINED & SAVED")