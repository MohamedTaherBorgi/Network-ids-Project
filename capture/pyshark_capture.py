"""
Pyshark Packet Capture Module
Deep packet inspection with protocol dissection
"""

import os
import pyshark
import pandas as pd
from datetime import datetime


class PysharkCapture:
    def __init__(self, interface=None, output_file="data/deep_packets.csv"):
        """
        Initialize Pyshark capture for deep inspection
        """
        self.interface = interface or "eth0"
        self.output_file = output_file
        self.packets_data = []

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

    def safe_get(self, layer, attr, default=""):
        """Safely get a layer attribute if it exists."""
        return getattr(layer, attr, default)

    def extract_deep_features(self, packet):
        """
        Extract detailed features using Pyshark's protocol dissection
        """
        features = {
            "timestamp": datetime.now().isoformat(),
            "length": self.safe_get(packet, "length", 0),
            "protocol": packet.highest_layer,
        }

        # ---------------- IP -----------------
        if hasattr(packet, "ip"):
            ip = packet.ip
            features.update({
                "src_ip": self.safe_get(ip, "src"),
                "dst_ip": self.safe_get(ip, "dst"),
                "ttl": self.safe_get(ip, "ttl", 0),
                "ip_flags": self.safe_get(ip, "flags"),
                "ip_id": self.safe_get(ip, "id", 0),
            })

        # ---------------- TCP -----------------
        if hasattr(packet, "tcp"):
            tcp = packet.tcp
            features.update({
                "src_port": self.safe_get(tcp, "srcport"),
                "dst_port": self.safe_get(tcp, "dstport"),
                "tcp_flags": self.safe_get(tcp, "flags"),
                "tcp_seq": self.safe_get(tcp, "seq", 0),
                "tcp_ack": self.safe_get(tcp, "ack", 0),
                "tcp_window": self.safe_get(tcp, "window_size", 0),
            })

        # ---------------- UDP -----------------
        if hasattr(packet, "udp"):
            udp = packet.udp
            features.update({
                "src_port": self.safe_get(udp, "srcport"),
                "dst_port": self.safe_get(udp, "dstport"),
                "udp_length": self.safe_get(udp, "length", 0),
            })

        # ---------------- HTTP -----------------
        if hasattr(packet, "http"):
            http = packet.http
            features.update({
                "http_method": self.safe_get(http, "request_method"),
                "http_uri": self.safe_get(http, "request_uri"),
                "http_host": self.safe_get(http, "host"),
                "http_user_agent": self.safe_get(http, "user_agent"),
            })

        # ---------------- DNS -----------------
        if hasattr(packet, "dns"):
            dns = packet.dns
            features.update({
                "dns_query": self.safe_get(dns, "qry_name"),
                "dns_type": self.safe_get(dns, "qry_type"),
            })

        # ---------------- ARP -----------------
        if hasattr(packet, "arp"):
            arp = packet.arp
            features.update({
                "arp_src_mac": self.safe_get(arp, "src_hw_mac"),
                "arp_dst_mac": self.safe_get(arp, "dst_hw_mac"),
                "arp_opcode": self.safe_get(arp, "opcode"),
            })

        return features

    def start_capture(self, callback=None, packet_count=100):
        """
        Start deep packet inspection capture
        """
        print(f"🔬 Starting PyShark deep inspection on {self.interface}...")
        print(f"💾 Output File: {self.output_file}")

        capture = pyshark.LiveCapture(interface=self.interface)

        try:
            for i, packet in enumerate(capture.sniff_continuously(packet_count=packet_count)):
                features = self.extract_deep_features(packet)
                self.packets_data.append(features)

                if callback:
                    callback(features)

                # Progress indicator
                if (i + 1) % 10 == 0:
                    print(f"Captured {i + 1}/{packet_count} packets...", end="\r")

            self.save_to_csv()
            print(f"\n✅ Deep inspection complete: {len(self.packets_data)} packets")

        except KeyboardInterrupt:
            print("\n⛔ Capture stopped by user")
            self.save_to_csv()

    def save_to_csv(self):
        """Save all captured packet data to CSV"""
        if not self.packets_data:
            print("⚠ No packets to save.")
            return

        df = pd.DataFrame(self.packets_data)
        df.to_csv(self.output_file, index=False)
        print(f"💾 Saved to {self.output_file}")


# ---------------------------- TEST MODE ----------------------------
if __name__ == "__main__":
    test_output = "capture_test_data/pyshark_test_packets.csv"
    os.makedirs("capture_test_data", exist_ok=True)

    capture = PysharkCapture(interface="eth2", output_file=test_output) #eth2 is Victim's connected Interface

    def test_callback(f):
        if "src_ip" in f:
            print(f"{f.get('src_ip', 'N/A')} → {f.get('dst_ip', 'N/A')} [{f['protocol']}]")

    capture.start_capture(callback=test_callback, packet_count=50)