# alerts.py
# Module responsible for managing intrusion detection alerts
# Displays alerts in real time, logs them to file, and exports to CSV for later analysis

import logging
from datetime import datetime
import os
import pandas as pd

# Create the logs directory if it doesn't exist
os.makedirs("logs", exist_ok=True)

# Configure the logger to write alerts to a file with timestamps
logging.basicConfig(
    filename='logs/alerts.log',
    level=logging.INFO,
    format='%(asctime)s | %(message)s'
)

# List that stores alerts in memory before periodic export to CSV
ALERTS = []

def log_alert(message, src="Unknown", dst="Unknown"):
    """
    Function to generate and record an alert when an intrusion is detected.
    
    It performs three actions:
    1. Prints the alert in red in the terminal for immediate visibility
    2. Writes the alert to the log file
    3. Stores alerts in memory and exports them to CSV every 20 alerts
       to allow post-analysis with tools like Pandas or Excel
    """
    time_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Create a dictionary with alert details
    alert = {
        "time": time_str,
        "message": message,
        "src": src,
        "dst": dst
    }
    ALERTS.append(alert)
   
    # Print colored alert in terminal (red for high visibility)
    print(f"\033[91m[ALERT] {time_str} | {message} | {src} → {dst}\033[0m")
   
    # Write to the log file
    logging.info(f"{message} | {src} → {dst}")
   
    # Every 20 alerts, export the buffer to CSV to avoid too many disk writes
    if len(ALERTS) % 20 == 0:
        os.makedirs("data/processed", exist_ok=True)
        df = pd.DataFrame(ALERTS)
        df.to_csv("data/processed/analyzed_alerts.csv", index=False)
