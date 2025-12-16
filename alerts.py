# alerts.py — FINAL
import logging
from datetime import datetime
import os
import pandas as pd

os.makedirs("logs", exist_ok=True)
logging.basicConfig(
    filename='logs/alerts.log',
    level=logging.INFO,
    format='%(asctime)s | %(message)s'
)

ALERTS = []

def log_alert(message, src="Unknown", dst="Unknown"):
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert = {
        "time": time_str,
        "message": message,
        "src": src,
        "dst": dst
    }
    ALERTS.append(alert)
    
    # Color in terminal
    print(f"\033[91m[ALERT] {time_str} | {message} | {src} → {dst}\033[0m")
    
    logging.info(f"{message} | {src} → {dst}")
    
    # Export every 20 alerts for performance
    if len(ALERTS) % 20 == 0:
        os.makedirs("data/processed", exist_ok=True)
        df = pd.DataFrame(ALERTS)
        df.to_csv("data/processed/analyzed_alerts.csv", index=False)
