# anomalies.py
import joblib
import numpy as np
import os
from utils import extract_features_scapy
from alerts import log_alert
from scapy.all import IP

MODEL_PATH = "data/model_isolation_forest.pkl"

def train_model():
    if not os.path.exists(MODEL_PATH):
        print("[*] Training Isolation Forest model...")
        from sklearn.ensemble import IsolationForest
        X = np.random.normal(100, 50, (1000, 5))
        X = np.vstack([X, np.random.normal(1000, 200, (50, 5))])  # some anomalies
        model = IsolationForest(contamination=0.05, random_state=42)
        model.fit(X)
        os.makedirs("data", exist_ok=True)
        joblib.dump(model, MODEL_PATH)
        print("[+] Model trained and saved")

def detect_anomaly_scapy(pkt):
    train_model()
    model = joblib.load(MODEL_PATH)
    feats = extract_features_scapy(pkt)
    if feats and model.predict([feats])[0] == -1:
        src = pkt[IP].src if pkt.haslayer(IP) else "?"
        dst = pkt[IP].dst if pkt.haslayer(IP) else "?"
        log_alert("ANOMALY DETECTED (Scapy) - Unusual traffic pattern", src, dst)

def detect_anomaly_pyshark(packet):
    train_model()
    model = joblib.load(MODEL_PATH)
    try:
        feats = [
            int(packet.length),
            int(packet.ip.proto),
            int(packet.tcp.srcport) if hasattr(packet, 'tcp') else 0,
            int(packet.tcp.dstport) if hasattr(packet, 'tcp') else 0,
            int(packet.tcp.flags, 16) if hasattr(packet, 'tcp') else 0
        ]
        if model.predict([feats])[0] == -1:
            log_alert("ANOMALY DETECTED (PyShark)", packet.ip.src, packet.ip.dst)
    except:
        pass