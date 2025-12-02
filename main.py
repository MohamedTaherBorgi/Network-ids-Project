import time
from capture_engine import PacketCaptureEngine
from feature_extractor import extract_features
from signature_based import SignatureBasedDetector
from ml_anomaly import MLAnomalyDetector
from alert_manager import AlertManager


def main():

    # --- Initialize Components ---
    capture = PacketCaptureEngine(
        interface="eth0",            # adjust as needed
        backend_name="scapy"         # or "pyshark"
    )

    signature_detector = SignatureBasedDetector(
        signature_file="config/signatures.yaml"
    )

    ml_detector = MLAnomalyDetector(
        model_path="models/anomaly_model.pkl",
        threshold=0.5
    )

    alerts = AlertManager(
        log_file="logs/ids.log",
        console_output=True
    )

    print("IDS started. Listening for packets...")


    # --- Packet Processing Loop ---
    try:
        for pkt in capture.capture_packets():

            # pkt here is a normalized dict from ScapyCapture or PysharkCapture
            features = extract_features(pkt)

            # 1. Signature-Based Detection
            for sig_id, description in signature_detector.evaluate_packet(features):
                alerts.send_alert(
                    alert_type=f"Signature [{sig_id}]",
                    description=description,
                    packet=features
                )

            # 2. ML-Based Anomaly Detection
            is_anom, score = ml_detector.evaluate(features)
            if is_anom:
                alerts.send_alert(
                    alert_type="ML-Anomaly",
                    description=f"Anomalous traffic detected (score={score})",
                    packet=features
                )

            # Prevent CPU overuse if packets are extremely fast
            time.sleep(0.0001)

    except KeyboardInterrupt:
        print("Stopping IDS...")

    finally:
        capture.stop()
        print("Capture stopped.")


if __name__ == "__main__":
    main()