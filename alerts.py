# alerts.py
import logging
from datetime import datetime
import os

os.makedirs("logs", exist_ok=True)
logging.basicConfig(filename='logs/alerts.log', level=logging.INFO,
                    format='%(asctime)s | %(message)s')

ALERTS = []

def log_alert(message, src="?", dst="?"):
    alert = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "message": message,
        "src": src,
        "dst": dst
    }
    ALERTS.append(alert)
    print(f"\033[91m[ALERT] {message} | {src} → {dst}\033[0m")
    logging.info(f"{message} | {src} → {dst}")