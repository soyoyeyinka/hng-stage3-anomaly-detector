import math
import statistics
import time
from collections import defaultdict, deque
from datetime import datetime, timezone


class BaselineManager:
    def __init__(self, config, audit_func):
        self.config = config
        self.audit = audit_func

        self.window_seconds = int(config.get("baseline_window_minutes", 30)) * 60
        self.recalc_seconds = int(config.get("baseline_recalc_seconds", 60))
        self.min_points = int(config.get("min_baseline_points", 10))
        self.hour_slot_min_points = int(config.get("hour_slot_min_points", 10))

        self.floor_mean = float(config.get("baseline_floor_mean", 0.05))
        self.floor_std = float(config.get("baseline_floor_std", 0.10))
        self.error_floor = float(config.get("error_rate_floor", 0.01))

        self.global_second_counts = defaultdict(int)
        self.global_second_errors = defaultdict(int)
        self.ip_second_counts = defaultdict(lambda: defaultdict(int))
        self.ip_second_errors = defaultdict(lambda: defaultdict(int))

        self.global_baseline = {
            "mean": self.floor_mean,
            "std": self.floor_std,
            "error_rate": self.error_floor,
            "points": 0,
            "source": "floor",
            "updated_at": None,
        }

        self.ip_baselines = defaultdict(lambda: {
            "mean": self.floor_mean,
            "std": self.floor_std,
            "error_rate": self.error_floor,
            "points": 0,
            "source": "floor",
            "updated_at": None,
        })

        self.hourly_global = defaultdict(lambda: deque(maxlen=240))
        self.hourly_ip = defaultdict(lambda: defaultdict(lambda: deque(maxlen=120)))

        self.last_recalc = 0

    def add_request(self, ip: str, is_error: bool, ts=None):
        second = int(ts or time.time())
        self.global_second_counts[second] += 1
        if is_error:
            self.global_second_errors[second] += 1

        if ip:
            self.ip_second_counts[ip][second] += 1
            if is_error:
                self.ip_second_errors[ip][second] += 1

    def _mean_std(self, values):
        if not values:
            return self.floor_mean, self.floor_std
        mean = max(statistics.mean(values), self.floor_mean)
        std = statistics.pstdev(values) if len(values) > 1 else self.floor_std
        std = max(std, self.floor_std)
        return mean, std

    def _current_hour(self):
        return datetime.now(timezone.utc).strftime("%H")

    def _cleanup(self, now):
        cutoff = int(now - self.window_seconds - 120)

        for key in list(self.global_second_counts.keys()):
            if key < cutoff:
                del self.global_second_counts[key]
        for key in list(self.global_second_errors.keys()):
            if key < cutoff:
                del self.global_second_errors[key]

        for ip in list(self.ip_second_counts.keys()):
            for key in list(self.ip_second_counts[ip].keys()):
                if key < cutoff:
                    del self.ip_second_counts[ip][key]
            for key in list(self.ip_second_errors[ip].keys()):
                if key < cutoff:
                    del self.ip_second_errors[ip][key]
            if not self.ip_second_counts[ip]:
                del self.ip_second_counts[ip]

    def recalculate(self):
        now = time.time()
        self._cleanup(now)

        end = int(now)
        start = max(0, end - self.window_seconds)
        seconds = list(range(start, end))

        global_counts = [self.global_second_counts.get(sec, 0) for sec in seconds]
        global_errors = [self.global_second_errors.get(sec, 0) for sec in seconds]

        g_mean, g_std = self._mean_std(global_counts)
        g_error = max(statistics.mean(global_errors), self.error_floor) if global_errors else self.error_floor

        hour = self._current_hour()
        last_minute_counts = [self.global_second_counts.get(sec, 0) for sec in range(max(0, end - 60), end)]
        last_minute_mean = statistics.mean(last_minute_counts) if last_minute_counts else 0
        self.hourly_global[hour].append(last_minute_mean)

        source = "rolling_30min"
        if len(self.hourly_global[hour]) >= self.hour_slot_min_points:
            h_mean, h_std = self._mean_std(list(self.hourly_global[hour]))
            g_mean, g_std = h_mean, h_std
            source = f"hour_slot_{hour}"

        self.global_baseline = {
            "mean": g_mean,
            "std": g_std,
            "error_rate": g_error,
            "points": len(global_counts),
            "source": source,
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        active_ips = list(self.ip_second_counts.keys())[:200]
        for ip in active_ips:
            counts = [self.ip_second_counts[ip].get(sec, 0) for sec in seconds]
            errors = [self.ip_second_errors[ip].get(sec, 0) for sec in seconds]

            i_mean, i_std = self._mean_std(counts)
            i_error = max(statistics.mean(errors), self.error_floor) if errors else self.error_floor

            last_ip_minute = [self.ip_second_counts[ip].get(sec, 0) for sec in range(max(0, end - 60), end)]
            last_ip_mean = statistics.mean(last_ip_minute) if last_ip_minute else 0
            self.hourly_ip[ip][hour].append(last_ip_mean)

            i_source = "rolling_30min"
            if len(self.hourly_ip[ip][hour]) >= self.hour_slot_min_points:
                h_mean, h_std = self._mean_std(list(self.hourly_ip[ip][hour]))
                i_mean, i_std = h_mean, h_std
                i_source = f"hour_slot_{hour}"

            self.ip_baselines[ip] = {
                "mean": i_mean,
                "std": i_std,
                "error_rate": i_error,
                "points": len(counts),
                "source": i_source,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }

        self.last_recalc = now
        self.audit(
            "BASELINE_RECALC",
            "global",
            f"source={source}",
            g_mean,
            f"mean={g_mean:.4f},std={g_std:.4f},error={g_error:.4f}",
            "n/a",
        )

    def should_recalculate(self):
        return time.time() - self.last_recalc >= self.recalc_seconds

    def get_global(self):
        return dict(self.global_baseline)

    def get_ip(self, ip: str):
        return dict(self.ip_baselines[ip])

    def zscore(self, rate: float, baseline: dict) -> float:
        std = max(float(baseline.get("std", self.floor_std)), self.floor_std)
        mean = float(baseline.get("mean", self.floor_mean))
        return (rate - mean) / std

    def hourly_summary(self):
        summary = []
        for hour, values in sorted(self.hourly_global.items()):
            vals = list(values)
            if vals:
                summary.append({
                    "hour": hour,
                    "effective_mean": round(statistics.mean(vals), 4),
                    "points": len(vals),
                })
        return summary[-12:]
