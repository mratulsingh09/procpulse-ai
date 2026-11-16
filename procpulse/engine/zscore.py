"""Rolling Z-score and EWMA baseline detector for single metrics."""

import math
from typing import Dict, Tuple, Optional, Any


class RollingEWMA:
    """Tracks Exponentially Weighted Moving Average (EWMA) and Moving Variance."""

    def __init__(self, alpha: float = 0.15, min_std: float = 1.0) -> None:
        """Initialize EWMA tracker.

        Args:
            alpha: Smoothing factor between 0.0 and 1.0.
            min_std: Minimum standard deviation floor to prevent division by zero.
        """
        self.alpha = alpha
        self.min_std = min_std
        self.count: int = 0
        self.mean: float = 0.0
        self.variance: float = 0.0

    def update(self, value: float) -> Tuple[float, float, float]:
        """Update tracker with a new metric observation and compute Z-score against prior baseline.

        Args:
            value: Observed float metric value.

        Returns:
            Tuple of (prior_mean, prior_std, z_score).
        """
        self.count += 1
        if self.count == 1:
            self.mean = value
            self.variance = 0.0
            return self.mean, self.min_std, 0.0

        # Prior baseline standard deviation and mean before absorbing current observation
        prior_mean = self.mean
        prior_std = max(math.sqrt(max(0.0, self.variance)), self.min_std)
        z_score = (value - prior_mean) / prior_std

        # Update mean and variance with EWMA
        delta = value - prior_mean
        self.mean = prior_mean + self.alpha * delta
        self.variance = (1.0 - self.alpha) * (self.variance + self.alpha * (delta ** 2))

        return prior_mean, prior_std, z_score


class ZScoreDetector:
    """Multi-metric statistical anomaly detector using rolling EWMA Z-scores."""

    def __init__(
        self,
        alpha: float = 0.15,
        low_threshold: float = 2.5,
        med_threshold: float = 3.5,
        high_threshold: float = 4.5,
    ) -> None:
        """Initialize ZScoreDetector.

        Args:
            alpha: EWMA smoothing factor.
            low_threshold: Z-score threshold for LOW severity.
            med_threshold: Z-score threshold for MEDIUM severity.
            high_threshold: Z-score threshold for HIGH severity.
        """
        self.alpha = alpha
        self.low_threshold = low_threshold
        self.med_threshold = med_threshold
        self.high_threshold = high_threshold

        # Dedicated EWMA trackers with calibrated minimum noise floors
        self.trackers: Dict[str, RollingEWMA] = {
            "cpu_percent": RollingEWMA(alpha=alpha, min_std=5.0),
            "mem_percent": RollingEWMA(alpha=alpha, min_std=3.0),
            "disk_io": RollingEWMA(alpha=alpha, min_std=50000.0),
            "net_io": RollingEWMA(alpha=alpha, min_std=50000.0),
        }

    def check(self, metric_name: str, value: float) -> Optional[Dict[str, Any]]:
        """Evaluate a metric value against its baseline.

        Args:
            metric_name: Name of metric (e.g., 'cpu_percent').
            value: Current numerical value.

        Returns:
            Anomaly dictionary if threshold exceeded, else None.
        """
        if metric_name not in self.trackers:
            self.trackers[metric_name] = RollingEWMA(alpha=self.alpha, min_std=1.0)

        tracker = self.trackers[metric_name]
        prior_mean, prior_std, z = tracker.update(value)

        # Only trigger for upward spikes above baseline
        if z >= self.low_threshold:
            if z >= self.high_threshold:
                severity = "high"
                score = min(1.0, 0.7 + (z - self.high_threshold) * 0.05)
            elif z >= self.med_threshold:
                severity = "medium"
                score = min(0.7, 0.4 + (z - self.med_threshold) * 0.2)
            else:
                severity = "low"
                score = min(0.4, 0.2 + (z - self.low_threshold) * 0.2)

            return {
                "metric": metric_name,
                "severity": severity,
                "score": round(score, 3),
                "value": round(value, 2),
                "baseline": round(prior_mean, 2),
                "z_score": round(z, 2),
            }

        return None
