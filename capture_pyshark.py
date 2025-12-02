# pyshark_capture.py
import pyshark
from signatures import check_signatures_pyshark
from anomalies import detect_anomaly_pyshark

INTERFACE = "eth0"  # Same as above

def pyshark_callback(packet):
    try:
        check_signatures_pyshark(packet)
        detect_anomaly_pyshark(packet)
    except:
        pass

def start_pyshark_capture():
    print(f"[PYSHARK] Starting capture on {INTERFACE} (tshark backend)...")
    capture = pyshark.LiveCapture(interface=INTERFACE, use_json=True)
    for packet in capture.sniff_continuously():
        pyshark_callback(packet)