"""Process behavioral fingerprinting for baseline statistical profiling."""

import math
import time
from typing import Dict, List, Tuple, Any, Optional


class ProcessFingerprinter:
    """Profiles and maintains baseline behavioral fingerprints for processes."""

    def __init__(self) -> None:
        """Initialize fingerprint registry."""
        # name -> {count, mean_cpu, m2_cpu, mean_mem, m2_mem, mean_fds, m2_fds, mean_threads, m2_threads}
        self.profiles: Dict[str, Dict[str, Any]] = {}

    def update(self, procs: List[Dict[str, Any]]) -> None:
        """Update fingerprints with new process telemetry observations.

        Uses Welford's algorithm for numerically stable online mean and variance.

        Args:
            procs: List of process telemetry dictionaries.
        """
        for p in procs:
            name = p.get("name", "unknown")
            cpu = float(p.get("cpu_percent", 0.0))
            mem = float(p.get("memory_rss", 0.0))
            fds = float(p.get("num_fds", 0))
            threads = float(p.get("num_threads", 1))

            if name not in self.profiles:
                self.profiles[name] = {
                    "count": 1,
                    "mean_cpu": cpu,
                    "m2_cpu": 0.0,
                    "mean_mem": mem,
                    "m2_mem": 0.0,
                    "mean_fds": fds,
                    "m2_fds": 0.0,
                    "mean_threads": threads,
                    "m2_threads": 0.0,
                    "last_updated": time.time(),
                }
                continue

            prof = self.profiles[name]
            prof["count"] += 1
            n = prof["count"]
            prof["last_updated"] = time.time()

            # Welford update for CPU
            d_cpu = cpu - prof["mean_cpu"]
            prof["mean_cpu"] += d_cpu / n
            prof["m2_cpu"] += d_cpu * (cpu - prof["mean_cpu"])

            # Welford update for Memory
            d_mem = mem - prof["mean_mem"]
            prof["mean_mem"] += d_mem / n
            prof["m2_mem"] += d_mem * (mem - prof["mean_mem"])

            # Welford update for FDs
            d_fds = fds - prof["mean_fds"]
            prof["mean_fds"] += d_fds / n
            prof["m2_fds"] += d_fds * (fds - prof["mean_fds"])

            # Welford update for Threads
            d_th = threads - prof["mean_threads"]
            prof["mean_threads"] += d_th / n
            prof["m2_threads"] += d_th * (threads - prof["mean_threads"])

    def get_fingerprint(self, name: str) -> Optional[Dict[str, Any]]:
        """Retrieve the computed baseline statistical fingerprint for a process name.

        Args:
            name: Process executable name.

        Returns:
            Dictionary with counts, means, and standard deviations, or None.
        """
        if name not in self.profiles:
            return None

        p = self.profiles[name]
        n = p["count"]
        std_cpu = math.sqrt(p["m2_cpu"] / n) if n > 1 else 1.0
        std_mem = math.sqrt(p["m2_mem"] / n) if n > 1 else 1024.0
        std_fds = math.sqrt(p["m2_fds"] / n) if n > 1 else 1.0
        std_threads = math.sqrt(p["m2_threads"] / n) if n > 1 else 1.0

        return {
            "name": name,
            "sample_count": n,
            "mean_cpu": round(p["mean_cpu"], 2),
            "std_cpu": round(std_cpu, 2),
            "mean_mem": round(p["mean_mem"], 1),
            "std_mem": round(std_mem, 1),
            "mean_fds": round(p["mean_fds"], 1),
            "std_fds": round(std_fds, 1),
            "mean_threads": round(p["mean_threads"], 1),
            "std_threads": round(std_threads, 1),
            "last_updated": p["last_updated"],
        }
