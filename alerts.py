import datetime
import os

LOG_PATH = "logs/alerts.log"

os.makedirs("logs", exist_ok=True)

def send_alert(message, src_ip="Unknown"):
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    alert_line = f"[{timestamp}] ALERT - {src_ip} - {message}\n"
    
    # Print to console (red color)
    print(f"\033[91m[!] {alert_line.strip()}\033[0m")
    
    # Write to log file
    with open(LOG_PATH, "a") as f:
        f.write(alert_line)
