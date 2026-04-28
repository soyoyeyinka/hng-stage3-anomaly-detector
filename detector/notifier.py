import requests
from datetime import datetime, timezone


class SlackNotifier:
    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url or ""

    def send(self, title: str, message: str):
        if not self.webhook_url or "PASTE_NEW_SLACK_WEBHOOK_URL_HERE" in self.webhook_url:
            print(f"[SLACK-SKIPPED] {title}: {message}", flush=True)
            return False

        payload = {
            "text": f"*{title}*\n{message}\n_Time: {datetime.now(timezone.utc).isoformat()}_"
        }

        try:
            response = requests.post(self.webhook_url, json=payload, timeout=5)
            return response.status_code < 400
        except Exception as exc:
            print(f"[SLACK-ERROR] {exc}", flush=True)
            return False
