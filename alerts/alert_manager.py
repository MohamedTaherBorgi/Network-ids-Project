import logging
import os
import time

class AlertManager:
    def __init__(self, log_file="logs/ids.log", console_output=True):
        self.console_output = console_output

        log_dir = os.path.dirname(log_file)
        if log_dir and not os.path.exists(log_dir):
            os.makedirs(log_dir)

        self.logger = logging.getLogger("IDS")
        self.logger.setLevel(logging.INFO)

        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            formatter = logging.Formatter(
                "%(asctime)s [%(levelname)s] %(message)s",
                "%Y-%m-%d %H:%M:%S",
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)

    def send_alert(self, alert_type, description, packet):
        ts = packet.get("ts")
        if ts is not None:
            ts_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
        else:
            ts_str = "N/A"

        src = packet.get("src", "N/A")
        dst = packet.get("dst", "N/A")
        proto = packet.get("proto", "N/A")

        msg = f"{alert_type} | {description} | {src} → {dst} | {proto} | {ts_str}"

        self.logger.info(msg)

        if self.console_output:
            print(msg)