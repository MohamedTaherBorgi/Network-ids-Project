# anomalies.py
# Module for machine learning-based anomaly detection using Isolation Forest
# Detects unusual traffic patterns that signature rules might miss

import joblib
import numpy as np
import os
import socket
import time
from collections import defaultdict
from utils import extract_features_scapy
from alerts import log_alert
from scapy.all import IP

# Path to the trained model file
MODEL_PATH = "data/model_isolation_forest.pkl"

# Debounce cache: ensures only one anomaly alert per source-destination flow every 5 seconds
# Prevents alert flooding during sustained anomalous activity
_last_anomaly = defaultdict(float)

def validate_ip(ip: str) -> bool:
    """
    Validates if a string is a proper IPv4 address.
    Used to filter out obviously spoofed or invalid IPs early.
    """
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def load_or_train_model():
    """
    Loads the pre-trained Isolation Forest model if it exists.
    If no model is found, creates a synthetic fallback model for basic functionality.
    The synthetic model is trained on generated normal and anomalous data
    to allow the system to run even without real training.
    """
    if os.path.exists(MODEL_PATH):
        data = joblib.load(MODEL_PATH)
        if isinstance(data, dict) and 'model' in data:
            return data['model'], data.get('scaler')
        return data, None
   
    print("[*] No model → synthetic fallback")
    from sklearn.ensemble import IsolationForest
    # Generate synthetic normal traffic data
    normal = np.random.normal([120, 6, 40000, 80, 18], [80, 5, 20000, 100, 20], (2000, 5))
    # Generate synthetic anomalous traffic data
    anomalies = np.random.normal([800, 1, 22, 22, 41], [300, 0, 10, 10, 50], (200, 5))
    X = np.vstack([normal, anomalies])
    # Train a basic Isolation Forest model
    model = IsolationForest(contamination=0.06, n_estimators=400, random_state=42)
    model.fit(X)
    os.makedirs("data", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    return model, None

# Load the model (real or synthetic) at startup
MODEL, SCALER = load_or_train_model()

def detect_anomaly_scapy(pkt):
    """
    Main anomaly detection function for Scapy-captured packets.
    Extracts features, runs prediction, and triggers debounced alerts on anomalies.
    """
    if not pkt.haslayer(IP):
        return
   
    try:
        src = pkt[IP].src
        dst = pkt[IP].dst
       
        # Drop obviously invalid/spoofed IPs without alerting
        if not validate_ip(src) or not validate_ip(dst):
            return
       
        feats = extract_features_scapy(pkt)
        if feats is None:
            return
       
        feats_array = np.array([feats])
        # Apply scaling if a scaler was saved during training
        if SCALER is not None:
            feats_array = SCALER.transform(feats_array)
       
        # Isolation Forest returns -1 for anomalies, 1 for normal
        if MODEL.predict(feats_array)[0] == -1:
            key = f"{src}->{dst}"
            now = time.time()
            # Debounce: only one alert per flow every 5 seconds
            if now - _last_anomaly[key] > 5:
                log_alert("ANOMALY DETECTED - Suspicious traffic flow", src, dst)
                _last_anomaly[key] = now
   
    except Exception:
        # Silent fail on any packet processing error to avoid crashing the capture loop
        pass

# PyShark anomaly detection is intentionally disabled to avoid duplicate alerts
# All ML detection is handled by the Scapy path for consistency
def detect_anomaly_pyshark(packet):
    pass  # Scapy handles anomaly detection
