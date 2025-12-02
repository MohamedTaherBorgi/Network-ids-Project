from collections import defaultdict, deque
from datetime import datetime, timedelta

# Rate tracking: IP → protocol → deque of timestamps
rate_tracker = defaultdict(lambda: defaultdict(lambda: deque()))

# Port scan tracking: IP → set of destination ports seen with SYN
port_scan_tracker = defaultdict(set)

def update_rate(ip, proto):
    """Track packets per second for a given IP + protocol"""
    now = datetime.now()
    bucket = rate_tracker[ip][proto]
    bucket.append(now)
    
    # Remove timestamps older than 1 second
    while bucket and bucket[0] < now - timedelta(seconds=1):
        bucket.popleft()
    
    return len(bucket)

def rate_exceeded(ip, proto, threshold=50):
    return update_rate(ip, proto) > threshold

def track_port_scan(ip, dport):
    """Simple port scan detection: > 20 different ports in < 5 seconds"""
    port_scan_tracker[ip].add(dport)
    # Clean old entries (optional: add timestamp later if needed)
    if len(port_scan_tracker[ip]) > 20:
        port_scan_tracker[ip].clear()
        return True
    return False

def reset_trackers():
    rate_tracker.clear()
    port_scan_tracker.clear()
