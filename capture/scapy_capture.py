"""
Scapy Packet Capture Module
Normal mode saves to data/captured_packets.csv
Test mode saves to capture_test_data/scapy_test_packets.csv
"""

import os
from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, ICMP
import pandas as pd
from datetime import datetime


class ScapyCapture:
    def __init__(self, interface=None, output_file="data/captured_packets.csv"):
        """
        Initialize Scapy packet capture
        """
        self.interface = interface
        self.output_file = output_file
        self.packets_data = []

        # Ensure directories exist
        os.makedirs(os.path.dirname(self.output_file), exist_ok=True)

    def extract_features(self, packet):
        """
        Extract features from packet for ML and analysis
        """
        if not packet.haslayer(IP):
            return None

        features = {
            "timestamp": datetime.now().isoformat(),
            "src_ip": packet[IP].src,
            "dst_ip": packet[IP].dst,
            "protocol": None,
            "src_port": 0,
            "dst_port": 0,
            "packet_size": len(packet),
            "ttl": packet[IP].ttl,
            "flags": "",
            "payload_size": 0,
        }

        if packet.haslayer(TCP):
            features["protocol"] = "TCP"
            features["src_port"] = packet[TCP].sport
            features["dst_port"] = packet[TCP].dport
            features["flags"] = str(packet[TCP].flags)

        elif packet.haslayer(UDP):
            features["protocol"] = "UDP"
            features["src_port"] = packet[UDP].sport
            features["dst_port"] = packet[UDP].dport

        elif packet.haslayer(ICMP):
            features["protocol"] = "ICMP"
            features["icmp_type"] = packet[ICMP].type
            features["icmp_code"] = packet[ICMP].code

        elif packet.haslayer(ARP):
            features["protocol"] = "ARP"
            features["src_mac"] = packet[ARP].hwsrc
            features["dst_mac"] = packet[ARP].hwdst

        if packet.haslayer(DNS) and packet[DNS].qd:
            features["dns_query"] = str(packet[DNS].qd.qname)

        if packet.haslayer("Raw"):
            features["payload_size"] = len(packet["Raw"].load)

        return features

    def start_capture(self, packet_callback=None, count=0):
        """
        Start capturing packets
        """
        print(f"🎧 Capturing on {self.interface}...")
        print(f"💾 Saving to: {self.output_file}")

        def combined_callback(pkt):
            features = self.extract_features(pkt)
            if features:
                self.packets_data.append(features)
                if packet_callback:
                    packet_callback(features)

        sniff(
            iface=self.interface,
            prn=combined_callback,
            store=0,
            count=count,
        )

        # Save after capture
        pd.DataFrame(self.packets_data).to_csv(self.output_file, index=False)
        print(f"✅ Saved {len(self.packets_data)} packets to {self.output_file}")


# ---------------------------- TEST MODE -----------------------------------

if __name__ == "__main__":
    """
    Test mode: Captures 100 packets and saves them to:
    capture_test_data/scapy_test_packets.csv
    """
    test_file = "capture_test_data/scapy_test_packets.csv"
    os.makedirs("capture_test_data", exist_ok=True)

    capture = ScapyCapture(interface="eth2", output_file=test_file) #eth2 is Victim's connected Interface

    def test_callback(features):
        print(f"{features['src_ip']} → {features['dst_ip']} [{features['protocol']}]")

    capture.start_capture(packet_callback=test_callback, count=50)
