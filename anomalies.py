import joblib # type: ignore
import numpy as np # type: ignore
import os
import socket
from utils import extract_features_scapy
from alerts import log_alert # type: ignore
from scapy.all import IP # type: ignore

MODEL_PATH = "data/model_isolation_forest.pkl"

def validate_ip(ip: str) -> bool:
    try:
        socket.inet_aton(ip)
        return True
    except socket.error:
        return False

def train_model():
    if os.path.exists(MODEL_PATH):
        return
    print("[*] No model found → training with synthetic data...")
    from sklearn.ensemble import IsolationForest
    normal = np.random.normal([100, 6, 35000, 35000, 2], [60, 3, 15000, 15000, 10], (1500, 5))
    anomalies = np.random.normal([1200, 1, 80, 80, 40], [400, 0, 20, 20, 50], (100, 5))
    X = np.vstack([normal, anomalies])
    model = IsolationForest(contamination=0.05, random_state=42, n_estimators=200, behaviour="new")
    model.fit(X)
    os.makedirs("data", exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    print(f"[+] Model trained and saved → {MODEL_PATH}")

def detect_anomaly_scapy(pkt):
    if not pkt.haslayer(IP):
        return
    src = pkt[IP].src
    dst = pkt[IP].dst
    if not validate_ip(src) or not validate_ip(dst):
        log_alert("INVALID TRAFFIC - Invalid IP address (Scapy)", src, dst)
        return
    train_model()
    model = joblib.load(MODEL_PATH)
    feats = extract_features_scapy(pkt)
    if feats is None:
        return
    if model.predict([feats])[0] == -1:
        log_alert("ANOMALY DETECTED (Scapy) - Unusual network behavior", src, dst)

def detect_anomaly_pyshark(packet):
    try:
        if not hasattr(packet, "ip"):
            return
        src = packet.ip.src
        dst = packet.ip.dst
        if not validate_ip(src) or not validate_ip(dst):
            log_alert("INVALID TRAFFIC - Invalid IP address (PyShark)", src, dst)
            return
        train_model()
        model = joblib.load(MODEL_PATH)
        feats = [
            int(packet.length),
            int(packet.ip.proto),
            int(packet.tcp.srcport) if hasattr(packet, "tcp") else 0,
            int(packet.tcp.dstport) if hasattr(packet, "tcp") else 0,
            int(packet.tcp.flags, 16) if hasattr(packet, "tcp") else 0,
        ]
        if model.predict([feats])[0] == -1:
            log_alert("ANOMALY DETECTED (PyShark) - Unusual network behavior", src, dst)
    except Exception:
        pass
