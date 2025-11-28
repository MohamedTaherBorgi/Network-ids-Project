"""
Pyshark Packet Capture Module
Deep packet inspection with protocol dissection
"""

import pyshark
import pandas as pd
from datetime import datetime

class PysharkCapture:
    def __init__(self, interface=None, output_file='data/deep_packets.csv'):
        """
        Initialize Pyshark capture for deep inspection
        
        Args:
            interface: Network interface
            output_file: Output CSV file
        """
        self.interface = interface or 'eth0'
        self.output_file = output_file
        self.packets_data = []
        
    def extract_deep_features(self, packet):
        """
        Extract detailed features using Pyshark's protocol dissection
        
        Returns:
            dict: Deep packet features
        """
        features = {
            'timestamp': datetime.now().isoformat(),
            'length': packet.length if hasattr(packet, 'length') else 0,
            'protocol': packet.highest_layer
        }
        
        try:
            # IP Layer
            if hasattr(packet, 'ip'):
                features['src_ip'] = packet.ip.src
                features['dst_ip'] = packet.ip.dst
                features['ttl'] = packet.ip.ttl
                features['ip_flags'] = packet.ip.flags if hasattr(packet.ip, 'flags') else ''
                features['ip_id'] = packet.ip.id if hasattr(packet.ip, 'id') else 0
            
            # TCP Layer
            if hasattr(packet, 'tcp'):
                features['src_port'] = packet.tcp.srcport
                features['dst_port'] = packet.tcp.dstport
                features['tcp_flags'] = packet.tcp.flags if hasattr(packet.tcp, 'flags') else ''
                features['tcp_seq'] = packet.tcp.seq if hasattr(packet.tcp, 'seq') else 0
                features['tcp_ack'] = packet.tcp.ack if hasattr(packet.tcp, 'ack') else 0
                features['tcp_window'] = packet.tcp.window_size if hasattr(packet.tcp, 'window_size') else 0
            
            # UDP Layer
            elif hasattr(packet, 'udp'):
                features['src_port'] = packet.udp.srcport
                features['dst_port'] = packet.udp.dstport
                features['udp_length'] = packet.udp.length
            
            # HTTP Layer (application level)
            if hasattr(packet, 'http'):
                features['http_method'] = packet.http.request_method if hasattr(packet.http, 'request_method') else ''
                features['http_uri'] = packet.http.request_uri if hasattr(packet.http, 'request_uri') else ''
                features['http_host'] = packet.http.host if hasattr(packet.http, 'host') else ''
                features['http_user_agent'] = packet.http.user_agent if hasattr(packet.http, 'user_agent') else ''
            
            # DNS Layer
            if hasattr(packet, 'dns'):
                features['dns_query'] = packet.dns.qry_name if hasattr(packet.dns, 'qry_name') else ''
                features['dns_type'] = packet.dns.qry_type if hasattr(packet.dns, 'qry_type') else ''
            
            # ARP Layer
            if hasattr(packet, 'arp'):
                features['arp_src_mac'] = packet.arp.src_hw_mac if hasattr(packet.arp, 'src_hw_mac') else ''
                features['arp_dst_mac'] = packet.arp.dst_hw_mac if hasattr(packet.arp, 'dst_hw_mac') else ''
                features['arp_opcode'] = packet.arp.opcode if hasattr(packet.arp, 'opcode') else ''
                
        except AttributeError as e:
            # Some packets may not have all layers
            pass
        
        return features
    
    def start_capture(self, callback=None, packet_count=100):
        """
        Start deep packet inspection capture
        
        Args:
            callback: Callback function for each packet
            packet_count: Number of packets to capture
        """
        print(f"🔬 Starting Pyshark deep inspection on {self.interface}...")
        
        capture = pyshark.LiveCapture(interface=self.interface)
        
        try:
            for i, packet in enumerate(capture.sniff_continuously(packet_count=packet_count)):
                features = self.extract_deep_features(packet)
                self.packets_data.append(features)
                
                if callback:
                    callback(features)
                
                # Progress
                if (i + 1) % 10 == 0:
                    print(f"Captured {i + 1} packets...", end='\r')
            
            # Save to CSV
            self.save_to_csv()
            print(f"\n✅ Deep inspection complete: {len(self.packets_data)} packets")
            
        except KeyboardInterrupt:
            print(f"\n✅ Capture stopped")
            self.save_to_csv()
    
    def save_to_csv(self):
        """Save captured data to CSV"""
        if self.packets_data:
            df = pd.DataFrame(self.packets_data)
            df.to_csv(self.output_file, index=False)
            print(f"💾 Saved to {self.output_file}")


# Test module
if __name__ == "__main__":
    capture = PysharkCapture()
    
    def test_callback(features):
        if 'src_ip' in features:
            print(f"{features.get('src_ip', 'N/A')} → {features.get('dst_ip', 'N/A')} [{features['protocol']}]")
    
    capture.start_capture(callback=test_callback, packet_count=20)
