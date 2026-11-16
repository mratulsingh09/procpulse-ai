"""Unified anomaly coordinator with warm-up logic and root-cause attribution."""

import time
import logging
from typing import Dict, List, Optional, Tuple, Any

from procpulse.config import settings
from procpulse.engine.zscore import ZScoreDetector
from procpulse.engine.isolation_forest import MultiMetricIsolationForest
from procpulse.engine.health_score import HealthScoreCalculator
from procpulse.engine.fingerprint import ProcessFingerprinter
from procpulse.engine.suspicious import SuspiciousProcessDetector

logger = logging.getLogger(__name__)


class AnomalyEngine:
    """Coordinates statistical, ML, health scoring, and process profiling detectors."""

    def __init__(
        self,
        warmup_samples: int = settings.warmup_samples,
        ewma_alpha: float = settings.ewma_alpha,
        low_threshold: float = settings.zscore_low_threshold,
        med_threshold: float = settings.zscore_medium_threshold,
        high_threshold: float = settings.zscore_high_threshold,
    ) -> None:
        """Initialize the unified anomaly engine.

        Args:
            warmup_samples: Number of ticks before raising alerts.
            ewma_alpha: Alpha smoothing factor for EWMA.
            low_threshold: Low severity Z-score threshold.
            med_threshold: Medium severity Z-score threshold.
            high_threshold: High severity Z-score threshold.
        """
        self.warmup_samples = warmup_samples
        self.tick_count: int = 0

        self.zscore_detector = ZScoreDetector(
            alpha=ewma_alpha,
            low_threshold=low_threshold,
            med_threshold=med_threshold,
            high_threshold=high_threshold,
        )
        self.isolation_forest = MultiMetricIsolationForest(
            contamination=settings.isolation_forest_contamination,
            history_size=settings.isolation_forest_history_size,
            retrain_interval_sec=settings.isolation_forest_retrain_interval_sec,
        )
        self.health_calculator = HealthScoreCalculator()
        self.fingerprinter = ProcessFingerprinter()
        self.suspicious_detector = SuspiciousProcessDetector()

        self.recent_anomalies: List[Dict[str, Any]] = []
        self.current_health_score: float = 100.0
        self.current_health_status: str = "healthy"
        self.active_suspicious: List[Dict[str, Any]] = []

    @property
    def is_warmed_up(self) -> bool:
        """Check if warm-up period is finished."""
        return self.tick_count >= self.warmup_samples

    def get_health_score(self) -> Tuple[float, str]:
        """Get latest health score and classification."""
        return self.current_health_score, self.current_health_status

    def get_active_anomalies(self) -> List[Dict[str, Any]]:
        """Get list of recent active anomalies."""
        return self.recent_anomalies

    def get_suspicious_processes(self) -> List[Dict[str, Any]]:
        """Get list of active suspicious process detections."""
        return self.active_suspicious

    def process_tick(
        self,
        system_data: Dict[str, Any],
        processes: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """Analyze a 1-second telemetry tick from collector.

        Args:
            system_data: System telemetry snapshot.
            processes: Top process snapshots.

        Returns:
            List of newly detected anomaly events.
        """
        self.tick_count += 1
        now = system_data.get("timestamp", time.time())

        # 1. Update multi-metric isolation forest buffer
        self.isolation_forest.add_sample(system_data)

        # 2. Update process baseline fingerprints
        self.fingerprinter.update(processes)

        # 3. Check for suspicious process behavior (e.g. sudden FD leaks)
        suspicious_alerts = self.suspicious_detector.check(processes)
        self.active_suspicious = suspicious_alerts

        # If still in warm-up period, train baselines and suppress alerts
        if not self.is_warmed_up:
            # Seed trackers
            self.zscore_detector.check("cpu_percent", system_data.get("cpu_percent", 0.0))
            self.zscore_detector.check("mem_percent", system_data.get("mem_percent", 0.0))
            total_disk = system_data.get("disk_read_bytes_sec", 0.0) + system_data.get("disk_write_bytes_sec", 0.0)
            self.zscore_detector.check("disk_io", total_disk)
            total_net = system_data.get("net_recv_bytes_sec", 0.0) + system_data.get("net_sent_bytes_sec", 0.0)
            self.zscore_detector.check("net_io", total_net)

            self.current_health_score = 100.0
            self.current_health_status = "healthy"
            return []

        # Find top processes for attribution
        top_cpu_proc = processes[0] if processes else None
        top_mem_proc = max(processes, key=lambda p: p.get("memory_percent", 0.0)) if processes else None

        new_anomalies: List[Dict[str, Any]] = []

        # 4. Check Single-Metric Z-Scores
        # A. CPU
        cpu_val = system_data.get("cpu_percent", 0.0)
        cpu_anom = self.zscore_detector.check("cpu_percent", cpu_val)
        if cpu_anom and cpu_val >= 25.0:  # Only report CPU anomalies if CPU is meaningfully elevated
            related_pid = top_cpu_proc.get("pid") if top_cpu_proc else None
            related_name = top_cpu_proc.get("name") if top_cpu_proc else "System"
            related_pct = top_cpu_proc.get("cpu_percent", 0.0) if top_cpu_proc else 0.0

            explanation = (
                f"CPU utilization surged to {cpu_val:.1f}% ({cpu_anom['z_score']:.1f}σ above "
                f"baseline of {cpu_anom['baseline']:.1f}%), caused mainly by PID {related_pid} "
                f"('{related_name}') consuming {related_pct:.1f}% CPU."
            )
            cpu_anom.update({
                "timestamp": now,
                "related_pid": related_pid,
                "related_process": related_name,
                "explanation": explanation,
            })
            new_anomalies.append(cpu_anom)

        # B. Memory
        mem_val = system_data.get("mem_percent", 0.0)
        mem_anom = self.zscore_detector.check("mem_percent", mem_val)
        if mem_anom and mem_val >= 40.0:
            related_pid = top_mem_proc.get("pid") if top_mem_proc else None
            related_name = top_mem_proc.get("name") if top_mem_proc else "System"
            related_pct = top_mem_proc.get("memory_percent", 0.0) if top_mem_proc else 0.0

            explanation = (
                f"Memory usage spiked to {mem_val:.1f}% ({mem_anom['z_score']:.1f}σ above "
                f"baseline of {mem_anom['baseline']:.1f}%), top consumer is PID {related_pid} "
                f"('{related_name}') using {related_pct:.1f}% RAM."
            )
            mem_anom.update({
                "timestamp": now,
                "related_pid": related_pid,
                "related_process": related_name,
                "explanation": explanation,
            })
            new_anomalies.append(mem_anom)

        # C. Disk I/O
        total_disk = system_data.get("disk_read_bytes_sec", 0.0) + system_data.get("disk_write_bytes_sec", 0.0)
        disk_anom = self.zscore_detector.check("disk_io", total_disk)
        if disk_anom and total_disk >= 5 * 1024 * 1024:  # At least 5MB/s to avoid noise
            mb_s = total_disk / (1024 * 1024)
            base_mb_s = disk_anom["baseline"] / (1024 * 1024)
            explanation = (
                f"Disk I/O burst of {mb_s:.1f} MB/s ({disk_anom['z_score']:.1f}σ above "
                f"baseline of {base_mb_s:.1f} MB/s)."
            )
            disk_anom.update({
                "timestamp": now,
                "related_pid": top_cpu_proc.get("pid") if top_cpu_proc else None,
                "related_process": top_cpu_proc.get("name") if top_cpu_proc else None,
                "explanation": explanation,
            })
            new_anomalies.append(disk_anom)

        # D. Network I/O
        total_net = system_data.get("net_recv_bytes_sec", 0.0) + system_data.get("net_sent_bytes_sec", 0.0)
        net_anom = self.zscore_detector.check("net_io", total_net)
        if net_anom and total_net >= 5 * 1024 * 1024:
            mb_s = total_net / (1024 * 1024)
            base_mb_s = net_anom["baseline"] / (1024 * 1024)
            explanation = (
                f"Network traffic burst of {mb_s:.1f} MB/s ({net_anom['z_score']:.1f}σ above "
                f"baseline of {base_mb_s:.1f} MB/s)."
            )
            net_anom.update({
                "timestamp": now,
                "related_pid": None,
                "related_process": None,
                "explanation": explanation,
            })
            new_anomalies.append(net_anom)

        # 5. Check Multi-Metric Isolation Forest
        if not new_anomalies:  # Only check IF if single metrics didn't already explain a simple spike
            if_anom = self.isolation_forest.predict(system_data)
            if if_anom:
                feat = if_anom.get("dominant_feature", "telemetry")
                explanation = (
                    f"Multi-metric correlation anomaly detected by IsolationForest (score {if_anom['score']:.2f}). "
                    f"Outlier dimension: {feat} at {if_anom['value']} ({if_anom['z_score']:.1f}σ deviation)."
                )
                if_anom.update({
                    "timestamp": now,
                    "related_pid": top_cpu_proc.get("pid") if top_cpu_proc else None,
                    "related_process": top_cpu_proc.get("name") if top_cpu_proc else None,
                    "explanation": explanation,
                })
                new_anomalies.append(if_anom)

        # Maintain recent anomalies list (keep last 50)
        self.recent_anomalies.extend(new_anomalies)
        self.recent_anomalies = self.recent_anomalies[-50:]

        # 6. Recalculate System Health Score
        # Filter anomalies to active in the last 30 seconds
        active_recent = [a for a in self.recent_anomalies if now - a.get("timestamp", 0) <= 30.0]
        self.current_health_score, self.current_health_status = self.health_calculator.calculate(
            system_data=system_data,
            active_anomalies=active_recent,
            suspicious_processes=self.active_suspicious,
        )

        return new_anomalies
