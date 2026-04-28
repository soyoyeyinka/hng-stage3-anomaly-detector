import time
import threading
from collections import defaultdict, deque, Counter
from datetime import datetime, timezone


class DetectionEngine:
    def __init__(self, config, baseline, blocker, notifier, audit_func):
        self.config = config
        self.baseline = baseline
        self.blocker = blocker
        self.notifier = notifier
        self.audit = audit_func

        self.lock = threading.RLock()
        self.window_seconds = int(config.get("window_seconds", 60))

        self.global_window = deque()
        self.global_error_window = deque()
        self.ip_windows = defaultdict(deque)
        self.ip_error_windows = defaultdict(deque)

        self.total_logs = 0
        self.top_ips = Counter()
        self.banned_ips = {}
        self.ban_history = defaultdict(int)
        self.global_rate = 0.0
        self.last_global_alert = 0
        self.start_time = time.time()

    def _evict(self, dq, now):
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    def _rate(self, dq):
        return len(dq) / max(self.window_seconds, 1)

    def _ban_duration(self, ip):
        schedule = self.config.get("ban_durations_seconds", [600, 1800, 7200, 0])
        index = min(self.ban_history[ip], len(schedule) - 1)
        return int(schedule[index])

    def _baseline_text(self, baseline):
        return f"mean={baseline['mean']:.4f},std={baseline['std']:.4f},source={baseline['source']}"

    def process(self, event):
        now = time.time()
        ip = event.get("source_ip") or "unknown"
        status = int(event.get("status") or 0)
        is_error = status >= 400

        with self.lock:
            self.total_logs += 1
            self.top_ips[ip] += 1

            self.global_window.append(now)
            self._evict(self.global_window, now)

            if is_error:
                self.global_error_window.append(now)
            self._evict(self.global_error_window, now)

            self.ip_windows[ip].append(now)
            self._evict(self.ip_windows[ip], now)

            if is_error:
                self.ip_error_windows[ip].append(now)
            self._evict(self.ip_error_windows[ip], now)

            self.baseline.add_request(ip, is_error, now)

            self.global_rate = self._rate(self.global_window)
            ip_rate = self._rate(self.ip_windows[ip])
            ip_error_rate = self._rate(self.ip_error_windows[ip])

            global_base = self.baseline.get_global()
            ip_base = self.baseline.get_ip(ip)

            if ip not in self.banned_ips:
                self._detect_ip(ip, ip_rate, ip_error_rate, ip_base)

            self._detect_global(self.global_rate, global_base)

    def _detect_ip(self, ip, rate, error_rate, baseline):
        error_surge_multiplier = float(self.config.get("error_surge_multiplier", 3.0))

        z_threshold = float(self.config.get("zscore_threshold", 3.0))
        multiplier = float(self.config.get("multiplier_threshold", 5.0))

        baseline_error = max(float(baseline.get("error_rate", 0.01)), 0.01)
        error_surge = error_rate >= error_surge_multiplier * baseline_error and error_rate > 0

        if error_surge:
            z_threshold = float(self.config.get("tight_zscore_threshold", 2.0))
            multiplier = float(self.config.get("tight_multiplier_threshold", 3.0))

        mean = max(float(baseline.get("mean", 0.05)), 0.05)
        z = self.baseline.zscore(rate, baseline)

        condition = None
        if z > z_threshold:
            condition = f"per_ip_zscore z={z:.2f} threshold={z_threshold}"
        elif rate > multiplier * mean:
            condition = f"per_ip_multiplier rate>{multiplier}x_mean"
        elif error_surge:
            condition = f"error_surge error_rate={error_rate:.4f} baseline_error={baseline_error:.4f}"

        if not condition:
            return

        duration = self._ban_duration(ip)
        blocked = self.blocker.block(ip)
        if not blocked:
            return

        self.ban_history[ip] += 1
        expires_at = None if duration == 0 else time.time() + duration

        self.banned_ips[ip] = {
            "ip": ip,
            "condition": condition,
            "rate": round(rate, 4),
            "baseline": self._baseline_text(baseline),
            "duration": duration,
            "expires_at": expires_at,
            "banned_at": datetime.now(timezone.utc).isoformat(),
        }

        duration_text = "permanent" if duration == 0 else f"{duration} seconds"

        self.audit("BAN", ip, condition, rate, self._baseline_text(baseline), duration_text)

        self.notifier.send(
            "???? HNG Detector: IP Banned",
            f"IP: `{ip}`\nCondition: `{condition}`\nCurrent rate: `{rate:.4f} req/s`\nBaseline: `{self._baseline_text(baseline)}`\nBan duration: `{duration_text}`",
        )

    def _detect_global(self, rate, baseline):
        now = time.time()
        cooldown = int(self.config.get("global_alert_cooldown_seconds", 120))
        if now - self.last_global_alert < cooldown:
            return

        z_threshold = float(self.config.get("zscore_threshold", 3.0))
        multiplier = float(self.config.get("multiplier_threshold", 5.0))
        mean = max(float(baseline.get("mean", 0.05)), 0.05)
        z = self.baseline.zscore(rate, baseline)

        condition = None
        if z > z_threshold:
            condition = f"global_zscore z={z:.2f} threshold={z_threshold}"
        elif rate > multiplier * mean:
            condition = f"global_multiplier rate>{multiplier}x_mean"

        if not condition:
            return

        self.last_global_alert = now
        self.audit("GLOBAL_ALERT", "global", condition, rate, self._baseline_text(baseline), "alert_only")

        self.notifier.send(
            "???? HNG Detector: Global Traffic Anomaly",
            f"Condition: `{condition}`\nCurrent global rate: `{rate:.4f} req/s`\nBaseline: `{self._baseline_text(baseline)}`\nAction: `Slack alert only, no global block`",
        )

    def unban_expired(self):
        now = time.time()
        expired = []

        with self.lock:
            for ip, info in list(self.banned_ips.items()):
                expires_at = info.get("expires_at")
                if expires_at and now >= expires_at:
                    expired.append((ip, info))

        for ip, info in expired:
            self.blocker.unblock(ip)
            with self.lock:
                self.banned_ips.pop(ip, None)

            self.audit("UNBAN", ip, "ban_expired", info.get("rate", 0), info.get("baseline", ""), "released")

            self.notifier.send(
                "✅ HNG Detector: IP Unbanned",
                f"IP: `{ip}`\nReason: `ban duration expired`\nPrevious condition: `{info.get('condition')}`",
            )

    def metrics(self):
        with self.lock:
            uptime = int(time.time() - self.start_time)
            banned = list(self.banned_ips.values())
            top = [{"ip": ip, "count": count} for ip, count in self.top_ips.most_common(10)]

            return {
                "uptime_seconds": uptime,
                "logs_processed": self.total_logs,
                "global_rate": round(self.global_rate, 4),
                "top_ips": top,
                "banned_ips": banned,
                "global_baseline": self.baseline.get_global(),
                "hourly_baseline": self.baseline.hourly_summary(),
            }
