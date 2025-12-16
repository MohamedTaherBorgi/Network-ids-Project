# anomalies.py — FINAL WITH DEBOUNCE (NO MORE 1000+ ALERTS)
import joblib
import numpy as np
import os
import socket
import time
from collections import defaultdict
from utils import extract_features_scapy
from alerts import log_alert
from scapy.all import IP

MODEL_PATH = "data/model_isolation_forest.pkl"

# Debounce cache: max 1 anomaly per (src->dst) every 5 seconds
_last_anomaly = defaultdict(float)

def validate_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def load_or_train_model():
    if os.path.exists(MODEL_PATH):
        data = joblib.load(MODEL_PATH)
        if isinstance(data, dict) and 'model' in data:
            return data['model'], data.get('scaler')
        return data, None
    
    print("[*] No model → synthetic fallback")
    from sklearn.ensemble import IsolationForest
    normal = np.random.normal([120, 6, 40000, 80, 18], [80, 5, 20000, 100, 20], (2000, 5))
    anomalies = np.random.normal([800, 1, 22, 22, 41], [300, 0, 10, 10, 50], (200, 5))
    X = np.vstack([normal, anomalies])
    model = IsolationForest(contamination=0.06, n_estimators=400, random_state=42)
    model.fit(X)
    os.makedirs("data", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    return model, None

MODEL, SCALER = load_or_train_model()

def detect_anomaly_scapy(pkt):
    if not pkt.haslayer(IP):
        return
    
    try:
        src = pkt[IP].src
        dst = pkt[IP].dst
        
        if not validate_ip(src) or not validate_ip(dst):
            return  # Silent drop spoofed
        
        feats = extract_features_scapy(pkt)
        if feats is None:
            return
        
        feats_array = np.array([feats])
        if SCALER is not None:
            feats_array = SCALER.transform(feats_array)
        
        if MODEL.predict(feats_array)[0] == -1:
            key = f"{src}->{dst}"
            now = time.time()
            if now - _last_anomaly[key] > 5:  # 1 anomaly per flow every 5s
                log_alert("ANOMALY DETECTED - Suspicious traffic flow", src, dst)
                _last_anomaly[key] = now
    
    except Exception:
        pass

# DISABLE PYSHARK ANOMALY TO AVOID DUPLICATES
def detect_anomaly_pyshark(packet):
    pass  # Intentionally disabled — Scapy handles ML
