# capture_pyshark.py — SIMPLE BACKUP ENGINE
import pyshark
from signatures import check_signatures_pyshark
from alerts import log_alert

INTERFACE = "eth1"

def start_pyshark_capture():
    print(f"[PYSHARK] Starting backup capture on {INTERFACE}...")

    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        bpf_filter="tcp or icmp"
    )

    try:
        for packet in capture.sniff_continuously():
            try:
                check_signatures_pyshark(packet)
            except Exception:
                pass  # Silent on bad packet
    except Exception as e:
        print(f"[PYSHARK] Capture stopped: {e}")

    print("[PYSHARK] Backup capture ended")
