import yaml
import os
import time


class SignatureBasedDetector:
    def __init__(self, signature_file="config/signatures.yaml"):
        if not os.path.exists(signature_file):
            raise FileNotFoundError(f"Missing signature file: {signature_file}")

        with open(signature_file, "r") as f:
            data = yaml.safe_load(f)

        self.signatures = data.get("signatures", [])
        self.validate_signatures()

        # per-signature counters
        self.counters = {}
        self.unique_dst = {}
        self.last_reset = time.time()

    def validate_signatures(self):
        allowed_keys = {
            "protocol",
            "src_port",
            "dst_port",
            "flag",
            "threshold_per_second",
            "time_window_seconds",
            "unique_dst_ports",
            "icmp_type",
            "min_query_length",
            "malformed",
        }

        for sig in self.signatures:
            if "id" not in sig or "description" not in sig:
                raise ValueError(f"Invalid signature: {sig}")

            cond = sig.get("conditions", {})
            for key in cond:
                if key not in allowed_keys:
                    raise ValueError(f"Unsupported condition key: {key}")

    def reset_counters(self):
        now = time.time()
        # reset each second
        if now - self.last_reset >= 1:
            self.counters = {}
            self.unique_dst = {}
            self.last_reset = now

    def evaluate_packet(self, pkt):
        self.reset_counters()

        for sig in self.signatures:
            cond = sig.get("conditions", {})
            if self.matches_signature(pkt, cond, sig["id"]):
                yield sig["id"], sig["description"]

    def matches_signature(self, pkt, cond, sig_id):
        proto = pkt.get("protocol")
        sport = pkt.get("sport")
        dport = pkt.get("dport")
        payload_len = pkt.get("payload_len")

        # protocol match
        if "protocol" in cond and cond["protocol"] != proto:
            return False

        # src port match
        if "src_port" in cond and cond["src_port"] != sport:
            return False

        # dst port match
        if "dst_port" in cond and cond["dst_port"] != dport:
            return False

        # flag match
        if "flag" in cond:
            flag = cond["flag"].upper()
            if flag == "S" and not pkt.get("syn"):
                return False
            if flag == "A" and not pkt.get("ack"):
                return False
            if flag == "F" and not pkt.get("fin"):
                return False
            if flag == "R" and not pkt.get("rst"):
                return False

        # threshold per second
        if "threshold_per_second" in cond:
            count = self.counters.get(sig_id, 0) + 1
            self.counters[sig_id] = count
            if count > cond["threshold_per_second"]:
                return True
            return False  # Do NOT match before threshold exceeded

        # minimum payload length
        if "min_query_length" in cond:
            if payload_len is None:
                return False
            if payload_len < cond["min_query_length"]:
                return False
            return True

        # unique destination ports
        if "unique_dst_ports" in cond:
            S = self.unique_dst.get(sig_id, set())
            S.add(dport)
            self.unique_dst[sig_id] = S
            if len(S) >= cond["unique_dst_ports"]:
                return True
            return False

        # malformed packet detector (simple boolean)
        if "malformed" in cond and cond["malformed"]:
            if proto is None or sport is None or dport is None:
                return True
            return False

        # If none of the special conditions apply:
        # packet matches only if the simple conditions above were satisfied
        return True