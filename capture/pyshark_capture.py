# capture_engine/pyshark_backend.py
import pyshark
import time

class PysharkCapture:
    def __init__(self, interface=None):
        self.interface = interface

    def start_capture(self, packet_callback):
        cap = pyshark.LiveCapture(interface=self.interface)
        for pkt in cap:
            try:
                self._process_packet(pkt, packet_callback)
            except Exception:
                continue

    def _process_packet(self, pkt, packet_callback):
        if not hasattr(pkt, "ip"):
            return

        src = pkt.ip.src
        dst = pkt.ip.dst
        proto = pkt.highest_layer
        length = int(pkt.length)

        sport = None
        dport = None
        flags = ""

        if hasattr(pkt, "tcp"):
            sport = pkt.tcp.srcport
            dport = pkt.tcp.dstport
            flags = pkt.tcp.flags

        elif hasattr(pkt, "udp"):
            sport = pkt.udp.srcport
            dport = pkt.udp.dstport

        payload = b""
        try:
            if hasattr(pkt, "data"):
                payload = bytes.fromhex(pkt.data.data.replace(":", ""))
        except Exception:
            pass

        packet = {
            "timestamp": time.time(),
            "src": src,
            "dst": dst,
            "protocol": proto,
            "length": length,
            "src_port": sport,
            "dst_port": dport,
            "flags": flags,
            "payload": payload,
        }

        packet_callback(packet)