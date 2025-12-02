import yaml
import os
import csv

from .scapy_capture import ScapyCapture
from .pyshark_capture import PysharkCapture
from processing.feature_extractor import extract_features


class CaptureEngine:
    def __init__(self, config_path="config/settings.yaml"):
        if not os.path.exists(config_path):
            raise FileNotFoundError(f"Missing config file: {config_path}")

        with open(config_path, "r") as f:
            config = yaml.safe_load(f)

        self.interface = config.get("interface", "eth0")
        backend_name = config.get("capture_backend", "scapy").lower()

        # Select backend
        if backend_name == "scapy":
            self.backend = ScapyCapture(interface=self.interface)
        elif backend_name == "pyshark":
            self.backend = PysharkCapture(interface=self.interface)
        else:
            raise ValueError(f"Unsupported capture backend: {backend_name}")

        # CSV output files
        self.raw_csv = "data/captured_packets.csv"
        self.deep_csv = "data/deep_packets.csv"

        self._ensure_csv_headers()

    def _ensure_csv_headers(self):
        if not os.path.exists(self.raw_csv):
            with open(self.raw_csv, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "src", "dst", "protocol", "length", "flags"])

        if not os.path.exists(self.deep_csv):
            with open(self.deep_csv, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow([
                    "ts", "src", "dst", "proto", "len",
                    "sport", "dport",
                    "syn", "ack", "fin", "rst", "psh", "urg",
                    "payload_len", "flow_id"
                ])

    def _packet_handler(self, pkt):
        # raw csv
        self._write_raw(pkt)

        # extract deep features
        features = extract_features(pkt)
        self._write_deep(features)

    def _write_raw(self, pkt):
        row = [
            pkt.get("timestamp"),
            pkt.get("src"),
            pkt.get("dst"),
            pkt.get("protocol"),
            pkt.get("length"),
            str(pkt.get("flags")),
        ]
        with open(self.raw_csv, "a", newline="") as f:
            csv.writer(f).writerow(row)

    def _write_deep(self, features):
        row = [
            features["ts"],
            features["src"],
            features["dst"],
            features["proto"],
            features["len"],
            features["sport"],
            features["dport"],
            features["syn"],
            features["ack"],
            features["fin"],
            features["rst"],
            features["psh"],
            features["urg"],
            features["payload_len"],
            features["flow_id"],
        ]
        with open(self.deep_csv, "a", newline="") as f:
            csv.writer(f).writerow(row)

    def run(self):
        # The backend will call _packet_handler for each packet
        self.backend.start_capture(packet_callback=self._packet_handler)