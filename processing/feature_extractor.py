import hashlib


def extract_features(pkt):

    ts = pkt.get("timestamp")
    src = pkt.get("src")
    dst = pkt.get("dst")
    proto = pkt.get("protocol")
    length = pkt.get("length")

    # -------- PORT EXTRACTION --------
    sport = None
    dport = None

    # Scapy does not extract ports → we must extract them from flags or payload
    # Better: ScapyCapture and PysharkCapture must add these fields
    if "src_port" in pkt:
        sport = pkt["src_port"]
    if "dst_port" in pkt:
        dport = pkt["dst_port"]

    # -------- FLAGS PARSING --------
    flags = pkt.get("flags")
    syn = ack = fin = rst = psh = urg = False

    if flags:
        flag_str = str(flags).upper()
        syn = "S" in flag_str
        ack = "A" in flag_str
        fin = "F" in flag_str
        rst = "R" in flag_str
        psh = "P" in flag_str
        urg = "U" in flag_str

    # -------- PAYLOAD LENGTH --------
    payload = pkt.get("payload")
    payload_len = len(payload) if payload else 0

    # -------- FLOW ID (better version) --------
    flow_string = f"{src}-{dst}-{proto}-{sport}-{dport}"
    flow_id = hashlib.md5(flow_string.encode()).hexdigest()

    return {
        "ts": ts,
        "src": src,
        "dst": dst,
        "proto": proto,
        "len": length,
        "sport": sport,
        "dport": dport,
        "syn": syn,
        "ack": ack,
        "fin": fin,
        "rst": rst,
        "psh": psh,
        "urg": urg,
        "payload_len": payload_len,
        "flow_id": flow_id,
    }