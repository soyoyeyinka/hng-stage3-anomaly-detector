import os
import time
import yaml
import threading
from datetime import datetime, timezone

from notifier import SlackNotifier
from blocker import IPTablesBlocker
from baseline import BaselineManager
from detector import DetectionEngine
from monitor import LogMonitor
from unbanner import Unbanner
from dashboard import create_dashboard


def load_config():
    with open("config.yaml", "r", encoding="utf-8") as file:
        return yaml.safe_load(file)


def make_audit_logger(path):
    os.makedirs(os.path.dirname(path), exist_ok=True)

    def audit(action, ip, condition, rate, baseline, duration):
        timestamp = datetime.now(timezone.utc).isoformat()
        line = f"[{timestamp}] {action} {ip} | {condition} | rate={rate} | baseline={baseline} | duration={duration}\n"
        with open(path, "a", encoding="utf-8") as file:
            file.write(line)
        print(line.strip(), flush=True)

    return audit


def baseline_loop(baseline):
    while True:
        if baseline.should_recalculate():
            baseline.recalculate()
        time.sleep(1)


def main():
    config = load_config()
    audit = make_audit_logger(config.get("audit_log", "/app/logs/audit.log"))

    notifier = SlackNotifier(config.get("slack_webhook_url"))
    blocker = IPTablesBlocker(config.get("protected_ips", []))
    baseline = BaselineManager(config, audit)
    engine = DetectionEngine(config, baseline, blocker, notifier, audit)

    monitor = LogMonitor(config.get("log_path"), engine)
    unbanner = Unbanner(engine)
    dashboard = create_dashboard(engine)

    audit("START", "system", "detector_started", 0, "n/a", "n/a")
    notifier.send("✅ HNG Detector Started", "The anomaly detection daemon is now running and watching Nginx JSON logs.")

    threading.Thread(target=monitor.follow, daemon=True).start()
    threading.Thread(target=baseline_loop, args=(baseline,), daemon=True).start()
    threading.Thread(target=unbanner.run, daemon=True).start()

    dashboard.run(
        host=config.get("dashboard_host", "0.0.0.0"),
        port=int(config.get("dashboard_port", 5050)),
        debug=False,
        use_reloader=False,
    )


if __name__ == "__main__":
    main()
