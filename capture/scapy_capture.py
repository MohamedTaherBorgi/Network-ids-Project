"""
Scapy Packet Capture Module
Captures network packets for real-time analysis
"""

from scapy.all import sniff, IP, TCP, UDP, ARP, DNS, ICMP
import pandas as pd
from datetime import datetime
import json

class ScapyCapture:
    def __init__(self, interface=None, output_file='data/captured_packets.csv'):
        """
        Initialize Scapy packet capture
        
        Args:
            interface: Network interface to capture on
            output_file: CSV file to save packets
        """
        self.interface = interface
        self.output_file = output_file
        self.packets_data = []
        self.packet_count = 0
        
    def extract_features(self, packet):
        """
        Extract features from packet for ML and analysis
        
        Returns:
            dict: Packet features
        """
        if not packet.haslayer(IP):
            return None
        
        features = {
            'timestamp': datetime.now().isoformat(),
            'src_ip': packet[IP].src,
            'dst_ip': packet[IP].dst,
            'protocol': None,
            'src_port': 0,
            'dst_port': 0,
            'packet_size': len(packet),
            'ttl': packet[IP].ttl,
            'flags': '',
            'payload_size': 0
        }
        
        # TCP
        if packet.haslayer(TCP):
            features['protocol'] = 'TCP'
            features['src_port'] = packet[TCP].sport
            features['dst_port'] = packet[TCP].dport
            features['flags'] = str(packet[TCP].flags)
            features['window_size'] = packet[TCP].window
            
        # UDP
        elif packet.haslayer(UDP):
            features['protocol'] = 'UDP'
            features['src_port'] = packet[UDP].sport
            features['dst_port'] = packet[UDP].dport
            
        # ICMP
        elif packet.haslayer(ICMP):
            features['protocol'] = 'ICMP'
            features['icmp_type'] = packet[ICMP].type
            features['icmp_code'] = packet[ICMP].code
            
        # ARP
        elif packet.haslayer(ARP):
            features['protocol'] = 'ARP'
            features['arp_op'] = packet[ARP].op
            features['src_mac'] = packet[ARP].hwsrc
            features['dst_mac'] = packet[ARP].hwdst
        
        # DNS
        if packet.haslayer(DNS):
            features['dns_query'] = str(packet[DNS].qd.qname) if packet[DNS].qd else ''
        
        # Payload
        if packet.haslayer('Raw'):
            features['payload_size'] = len(packet['Raw'].load)
        
        return features
    
    def packet_callback(self, packet):
        """
        Callback for each captured packet
        
        Args:
            packet: Scapy packet object
        """
        features = self.extract_features(packet)
        
        if features:
            self.packets_data.append(features)
            self.packet_count += 1
            
            # Save to CSV every 100 packets
            if self.packet_count % 100 == 0:
                self.save_to_csv()
                print(f"💾 Saved {self.packet_count} packets to {self.output_file}")
        
        return features
    
    def save_to_csv(self):
        """Save captured packets to CSV using Pandas"""
        if self.packets_data:
            df = pd.DataFrame(self.packets_data)
            
            # Append to existing file or create new
            try:
                df.to_csv(self.output_file, mode='a', header=False, index=False)
            except FileNotFoundError:
                df.to_csv(self.output_file, mode='w', header=True, index=False)
            
            # Clear memory
            self.packets_data = []
    
    def start_capture(self, packet_callback=None, count=0):
        """
        Start capturing packets
        
        Args:
            packet_callback: Optional additional callback function
            count: Number of packets to capture (0 = infinite)
        """
        print(f"🎧 Starting Scapy capture on {self.interface}...")
        print(f"💾 Saving to: {self.output_file}")
        
        def combined_callback(pkt):
            features = self.packet_callback(pkt)
            if packet_callback and features:
                packet_callback(features)
        
        try:
            sniff(
                iface=self.interface,
                prn=combined_callback,
                store=0,
                count=count
            )
        except KeyboardInterrupt:
            print(f"\n✅ Capture stopped. Total: {self.packet_count} packets")
            self.save_to_csv()
        except PermissionError:
            print("❌ Error: Root privileges required!")
            print("Run with: sudo python main.py")
            raise


# Test module
if __name__ == "__main__":
    capture = ScapyCapture(output_file='test_packets.csv')
    
    def test_callback(features):
        print(f"{features['src_ip']}:{features['src_port']} → "
              f"{features['dst_ip']}:{features['dst_port']} [{features['protocol']}]")
    
    capture.start_capture(packet_callback=test_callback, count=50)
