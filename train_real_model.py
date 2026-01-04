# train_real_model.py
# Script for capturing normal network traffic and training the Isolation Forest model
# This is used to create a baseline of legitimate traffic so the anomaly detector can identify deviations
# Run this before starting the full IDS to have an accurate real-traffic model instead of the synthetic fallback

from scapy.all import sniff
from utils import extract_features_scapy
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import joblib
import os
import sys

# Allow interface to be specified as command-line argument, default to eth1
# Useful when the VM interface name changes
INTERFACE = sys.argv[1] if len(sys.argv) > 1 else "eth1"

# Informative startup messages to guide the user
print(f"[*] Using interface: {INTERFACE}")
print("[*] Capturing packets for training — generate NORMAL traffic on victim VM")
print("[*] Goal: 1000+ packets for high-accuracy model")
print("[*] Press Ctrl+C when done\n")

# List to accumulate feature vectors from normal packets
features = []

def callback(pkt):
    """
    Callback function called for each captured packet.
    Extracts the 5 features defined in utils.py and adds them to the training list.
    Prints progress every 50 packets so the user knows it's working.
    """
    feats = extract_features_scapy(pkt)
    if feats:
        features.append(feats)
        if len(features) % 50 == 0:
            print(f"Captured {len(features)} packets...", end='\r')

try:
    # Start sniffing with a filter for IP packets only (reduces noise)
    # Promiscuous mode required to see all traffic on the segment
    sniff(
        iface=INTERFACE,
        prn=callback,
        filter="ip",
        promisc=True,
        store=False,      # Don't keep full packets in memory - we only need features
        timeout=None      # Run indefinitely until Ctrl+C
    )
except KeyboardInterrupt:
    # Expected way to stop capture
    print("\n[!] Capture stopped by user")
except Exception as e:
    # Catch unexpected errors during capture
    print(f"\n[!] Capture error: {e}")

# Safety check - require at least 500 normal samples for a reliable model
if len(features) < 500:
    print(f"\n[!] Only {len(features)} packets captured — too few!")
    print(" • Generate more normal traffic")
    print(" • Use Bridged mode")
    sys.exit(1)

# Convert collected features to numpy array for training
X_raw = np.array(features)

# Standardize features - important for Isolation Forest performance
scaler = StandardScaler()
X = scaler.fit_transform(X_raw)

# Training status message
print(f"\n[+] Captured {len(X)} normal samples — training optimized model...")

# Create and train the Isolation Forest model
# contamination=0.05 assumes ~5% of real traffic could be anomalous
# 500 trees for better accuracy without too much overhead
model = IsolationForest(
    contamination=0.05,
    n_estimators=500,
    max_samples='auto',
    random_state=42
)
model.fit(X)

# Save both the model and the scaler so they can be loaded together during detection
os.makedirs("data", exist_ok=True)
joblib.dump({
    'model': model,
    'scaler': scaler,
    'samples': len(X)
}, "data/model_isolation_forest.pkl")

# Success messages summarizing what was done
print("[+] OPTIMIZED MODEL TRAINED & SAVED")
print(" → Standardized features")
print(" → 500 trees")
print(" → High-accuracy anomaly detection ready")
print(" → Now run: ./run.sh")
