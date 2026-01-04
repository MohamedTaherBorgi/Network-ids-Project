# capture_pyshark.py
# Backup packet capture engine using PyShark
# This module runs as a secondary capture thread when selected in main.py
# It provides redundancy in case Scapy has issues and demonstrates use of the required PyShark tool

import pyshark
from signatures import check_signatures_pyshark
from alerts import log_alert

# Network interface to listen on - change if your Kali VM uses a different name (e.g., enp0s3)
INTERFACE = "eth1"

def start_pyshark_capture():
    """
    Starts the PyShark live capture loop.
    Applies only the PyShark-specific signature checks to avoid duplicate alerts with Scapy.
    Uses a BPF filter to reduce overhead by focusing on TCP and ICMP traffic only.
    """
    print(f"[PYSHARK] Starting backup capture on {INTERFACE}...")
    
    # Create LiveCapture object with BPF filter for efficiency
    capture = pyshark.LiveCapture(
        interface=INTERFACE,
        bpf_filter="tcp or icmp"
    )
    
    try:
        # Continuous sniffing loop - processes packets as they arrive
        for packet in capture.sniff_continuously():
            try:
                # Run the dedicated PyShark signature checks
                check_signatures_pyshark(packet)
            except Exception:
                # Silent exception handling to prevent one bad packet from stopping the whole capture
                pass  # Silent on bad packet
                
    except Exception as e:
        # Catch any fatal errors in the capture loop (e.g., interface down)
        print(f"[PYSHARK] Capture stopped: {e}")
        
    # Normal shutdown message
    print("[PYSHARK] Backup capture ended")
