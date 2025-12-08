import logging
from datetime import datetime
import os
import pandas as pd # type: ignore

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
    # Pandas export
    if len(ALERTS) % 10 == 0:
        os.makedirs("data/processed", exist_ok=True)
        df = pd.DataFrame(ALERTS)
        df.to_csv("data/processed/analyzed_alerts.csv", index=False)
