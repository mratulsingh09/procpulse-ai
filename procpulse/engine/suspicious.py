"""Suspicious process detector (sudden FD growth, thread explosion, resource leaks)."""

import time
import logging
from typing import Dict, List, Any

logger = logging.getLogger(__name__)


class SuspiciousProcessDetector:
    """Monitors per-process trajectories to identify suspicious behaviors and resource leaks."""

    def __init__(self) -> None:
        """Initialize detector state."""
        # pid -> {'name': str, 'last_fds': int, 'last_threads': int, 'history': [(t, fds, threads)]}
        self.history: Dict[int, Dict[str, Any]] = {}
        self.active_alerts: List[Dict[str, Any]] = []

    def check(self, procs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Evaluate processes for suspicious growth patterns.

        Args:
            procs: List of current process telemetry snapshots.

        Returns:
            List of detected suspicious process alerts.
        """
        now = time.time()
        new_alerts: List[Dict[str, Any]] = []
        current_pids = set()

        for p in procs:
            pid = p.get("pid", 0)
            if pid <= 1:
                continue
            current_pids.add(pid)

            name = p.get("name", "unknown")
            fds = p.get("num_fds", 0)
            threads = p.get("num_threads", 1)
            cpu = p.get("cpu_percent", 0.0)
            mem = p.get("memory_percent", 0.0)

            if pid not in self.history:
                self.history[pid] = {
                    "name": name,
                    "first_seen": now,
                    "samples": [(now, fds, threads)],
                }
                continue

            record = self.history[pid]
            record["name"] = name
            samples = record["samples"]
            samples.append((now, fds, threads))
            # Keep last 30 seconds of samples
            record["samples"] = [s for s in samples if now - s[0] <= 30.0]

            # 1. Check for Sudden File Descriptor Leaks
            # Compare current FDs to the earliest sample within the window
            earliest_t, earliest_fds, earliest_threads = record["samples"][0]
            delta_fds = fds - earliest_fds
            delta_threads = threads - earliest_threads
            elapsed = max(1.0, now - earliest_t)

            if delta_fds >= 25 and (fds >= 30) and (fds > earliest_fds * 1.5):
                alert = {
                    "timestamp": now,
                    "pid": pid,
                    "name": name,
                    "type": "fd_leak",
                    "severity": "high" if delta_fds >= 50 else "medium",
                    "reason": (
                        f"Rapid FD growth: +{delta_fds} open file descriptors in {round(elapsed, 1)}s "
                        f"(jumped from {earliest_fds} to {fds}) - potential resource or socket descriptor leak"
                    ),
                    "metrics": {
                        "num_fds": fds,
                        "fd_growth": delta_fds,
                        "num_threads": threads,
                        "cpu_percent": cpu,
                        "memory_percent": mem,
                    },
                }
                new_alerts.append(alert)

            # 2. Check for Thread Explosion
            if delta_threads >= 20 and threads >= 25:
                alert = {
                    "timestamp": now,
                    "pid": pid,
                    "name": name,
                    "type": "thread_explosion",
                    "severity": "high",
                    "reason": (
                        f"Rapid thread proliferation: +{delta_threads} threads spawned in {round(elapsed, 1)}s "
                        f"(jumped from {earliest_threads} to {threads})"
                    ),
                    "metrics": {
                        "num_fds": fds,
                        "num_threads": threads,
                        "thread_growth": delta_threads,
                        "cpu_percent": cpu,
                        "memory_percent": mem,
                    },
                }
                new_alerts.append(alert)

        # Clean up vanished PIDs
        for pid in list(self.history.keys()):
            if pid not in current_pids:
                del self.history[pid]

        self.active_alerts = new_alerts
        return new_alerts
