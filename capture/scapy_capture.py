# capture_engine/scapy_backend.py
from scapy.all import sniff, TCP, UDP, Raw, IP
import time

class ScapyCapture:
    def __init__(self, interface=None):
        self.interface = interface

    def start_capture(self, packet_callback):
        sniff(
            iface=self.interface,
            prn=lambda pkt: self._process_packet(pkt, packet_callback),
            store=False
        )

    def _process_packet(self, pkt, packet_callback):
        try:
            if IP not in pkt:
                return

            src = pkt[IP].src
            dst = pkt[IP].dst
            proto = pkt[IP].proto
            length = len(pkt)

            sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else None)
            dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else None)

            flags = pkt[TCP].flags if TCP in pkt else None

            payload = bytes(pkt[Raw].load) if Raw in pkt else b""

            packet = {
                "timestamp": time.time(),
                "src": src,
                "dst": dst,
                "protocol": proto,
                "length": length,
                "src_port": sport,
                "dst_port": dport,
                "flags": str(flags) if flags else "",
                "payload": payload,
            }

            packet_callback(packet)

        except Exception:
            pass