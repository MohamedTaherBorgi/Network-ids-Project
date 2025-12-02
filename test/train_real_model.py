# train_real_model.py  ← create this file
from scapy.all import sniff
from utils import extract_features_scapy
import numpy as np
from sklearn.ensemble import IsolationForest
import joblib
import os

print("Capturing 500 normal packets to train the model... (wait ~60 sec)")

features = []
def callback(pkt):
    feats = extract_features_scapy(pkt)
    if feats:
        features.append(feats)
    if len(features) >= 500:
        raise StopIteration

sniff(iface="eth0", prn=callback, timeout=120, filter="ip")

X = np.array(features)
print(f"Captured {len(X)} normal packets → training model...")

model = IsolationForest(contamination=0.03, random_state=42, n_estimators=100)
model.fit(X)

os.makedirs("data", exist_ok=True)
joblib.dump(model, "data/model_isolation_forest.pkl")
print("REAL MODEL TRAINED AND SAVED → anomalies.py will now use it!")
