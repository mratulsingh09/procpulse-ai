"""Multi-metric Isolation Forest anomaly detector with periodic retraining."""

import time
import math
import logging
from typing import List, Dict, Optional, Any
import numpy as np
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)


class MultiMetricIsolationForest:
    """Detects complex multi-dimensional system metric anomalies using IsolationForest."""

    FEATURE_NAMES = [
        "cpu_percent",
        "mem_percent",
        "disk_io_rate",
        "net_io_rate",
        "ctx_switches_sec",
        "interrupts_sec",
    ]

    def __init__(
        self,
        contamination: float = 0.03,
        history_size: int = 300,
        retrain_interval_sec: int = 60,
    ) -> None:
        """Initialize MultiMetricIsolationForest detector.

        Args:
            contamination: Expected proportion of outliers in the training data.
            history_size: Maximum rolling history window length.
            retrain_interval_sec: Interval in seconds between background retrainings.
        """
        self.contamination = contamination
        self.history_size = history_size
        self.retrain_interval_sec = retrain_interval_sec

        self.history: List[List[float]] = []
        self.model: Optional[IsolationForest] = None
        self.last_trained_time: float = 0.0
        self.feature_means: Optional[np.ndarray] = None
        self.feature_stds: Optional[np.ndarray] = None

    def _extract_vector(self, data: Dict[str, Any]) -> List[float]:
        """Convert system metric snapshot to normalized feature vector."""
        cpu = float(data.get("cpu_percent", 0.0))
        mem = float(data.get("mem_percent", 0.0))
        disk_total = float(data.get("disk_read_bytes_sec", 0.0)) + float(data.get("disk_write_bytes_sec", 0.0))
        net_total = float(data.get("net_recv_bytes_sec", 0.0)) + float(data.get("net_sent_bytes_sec", 0.0))
        ctx = float(data.get("ctx_switches_sec", 0.0))
        intr = float(data.get("interrupts_sec", 0.0))

        # Log-transform high-dynamic-range I/O rates
        return [
            cpu,
            mem,
            math.log1p(disk_total),
            math.log1p(net_total),
            ctx,
            intr,
        ]

    def add_sample(self, data: Dict[str, Any]) -> None:
        """Add a telemetry sample to the training history buffer.

        Args:
            data: System metric dictionary.
        """
        vec = self._extract_vector(data)
        self.history.append(vec)
        if len(self.history) > self.history_size:
            self.history.pop(0)

        # Trigger retraining if interval elapsed and enough samples exist
        now = time.time()
        if (now - self.last_trained_time >= self.retrain_interval_sec) and len(self.history) >= 30:
            self.train()

    def train(self) -> bool:
        """Train or retrain the IsolationForest model on accumulated history.

        Returns:
            True if trained successfully, False otherwise.
        """
        if len(self.history) < 20:
            return False

        try:
            X = np.array(self.history, dtype=np.float64)
            # If training set has near zero variance, add subtle numerical jitter so trees can split
            stds = np.std(X, axis=0)
            if np.all(stds < 1e-3):
                rng = np.random.RandomState(42)
                X = X + rng.normal(0, 0.05, X.shape)

            clf = IsolationForest(
                n_estimators=50,
                contamination=self.contamination,
                random_state=42,
                n_jobs=1,
            )
            clf.fit(X)
            self.model = clf
            self.feature_means = np.mean(X, axis=0)
            self.feature_stds = np.std(X, axis=0) + 1e-4
            self.last_trained_time = time.time()
            logger.debug("IsolationForest trained on %d samples.", len(self.history))
            return True
        except Exception as e:
            logger.error("Error training IsolationForest: %s", e)
            return False

    def predict(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Predict whether the current multi-metric state is an anomaly.

        Args:
            data: System metric dictionary.

        Returns:
            Anomaly dictionary if detected, else None.
        """
        if not self.model or self.feature_means is None or self.feature_stds is None:
            return None

        vec = self._extract_vector(data)
        X = np.array([vec], dtype=np.float64)

        try:
            decision = float(self.model.decision_function(X)[0])
            pred = int(self.model.predict(X)[0])  # -1 is anomaly, 1 is inlier

            if pred == -1 or decision < 0.0:
                # Find dominant contributing feature
                z_scores = (X[0] - self.feature_means) / self.feature_stds
                top_idx = int(np.argmax(np.abs(z_scores)))
                dominant_feature = self.FEATURE_NAMES[top_idx]
                dominant_z = float(z_scores[top_idx])

                severity = "high" if decision < -0.1 else "medium"
                score = round(min(1.0, max(0.0, -decision * 3.0)), 3)

                return {
                    "metric": "multi_metric_cluster",
                    "severity": severity,
                    "score": score,
                    "value": round(float(vec[top_idx]), 2),
                    "baseline": round(float(self.feature_means[top_idx]), 2),
                    "z_score": round(dominant_z, 2),
                    "dominant_feature": dominant_feature,
                    "decision_score": round(decision, 4),
                }
        except Exception as e:
            logger.debug("IsolationForest prediction error: %s", e)

        return None
