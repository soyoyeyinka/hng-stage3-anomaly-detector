import json
import os
import time


class LogMonitor:
    def __init__(self, log_path, engine):
        self.log_path = log_path
        self.engine = engine

    def follow(self):
        print(f"[MONITOR] Waiting for log file: {self.log_path}", flush=True)

        while not os.path.exists(self.log_path):
            time.sleep(1)

        print(f"[MONITOR] Tailing log file: {self.log_path}", flush=True)

        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as file:
            file.seek(0, os.SEEK_END)

            while True:
                line = file.readline()
                if not line:
                    time.sleep(0.2)
                    continue

                line = line.strip()
                if not line:
                    continue

                try:
                    event = json.loads(line)
                    self.engine.process(event)
                    print(f"[LOG] {event.get('source_ip')} {event.get('method')} {event.get('path')} {event.get('status')}", flush=True)
                except Exception as exc:
                    print(f"[PARSE-ERROR] {exc} | {line[:200]}", flush=True)
