"""
Main entry point for the Network Intrusion Detection System (NIDS)
Handles:
    - Packet capture (Scapy or Pyshark)
    - Feature extraction
    - Signature-based detection
    - Alert logging and console output
"""

import time
from capture.scapy_capture import ScapyCapture
from feature_extraction.feature_extractor import FeatureExtractor
from detection.signature_based import SignatureDetector
from alerts.alert_manager import AlertManager


def print_alert(alert):
    """Pretty console output for real-time alerts"""
    print("\n" + "=" * 60)
    print(f" 🚨 ALERT: {alert['alert_type']}  |  Severity: {alert['severity']}")
    print("-" * 60)
    print(f"Message: {alert['message']}")
    print(f"Source:      {alert.get('src_ip', 'N/A')}")
    print(f"Destination: {alert.get('dst_ip', 'N/A')}")
    print(f"Detection:   {alert['detection_method']}")
    print("=" * 60 + "\n")


def main():
    print("\n===== Network IDS Started =====")
    print("Capturing packets and monitoring network traffic...\n")

    # Initialize modules
    capture = ScapyCapture(interface="eth0")          # adjust if needed
    extractor = FeatureExtractor()
    signatures = SignatureDetector()
    alert_mgr = AlertManager()

    # Live capture
    for raw_pkt in capture.start_capture_live():

        # Step 1: Extract features (convert raw packet → dict)
        pkt = extractor.extract_features(raw_pkt)
        if pkt is None:
            continue

        # Step 2: Run signature-based detection
        alerts = signatures.detect_all(pkt)

        # Step 3: Handle alerts
        for alert in alerts:
            alert_mgr.save_alert(alert)   # store in SQLite / logs.db
            print_alert(alert)            # show on screen

        # Prevent CPU overload
        time.sleep(0.001)


if __name__ == "__main__":
    main()
