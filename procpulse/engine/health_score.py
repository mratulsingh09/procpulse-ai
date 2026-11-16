"""System Health Score calculator (0-100) based on telemetry pressure and active anomalies."""

from typing import Dict, List, Tuple, Any


class HealthScoreCalculator:
    """Calculates an overall real-time composite System Health Score (0-100)."""

    def calculate(
        self,
        system_data: Dict[str, Any],
        active_anomalies: List[Dict[str, Any]],
        suspicious_processes: List[Dict[str, Any]],
    ) -> Tuple[float, str]:
        """Compute the current system health score and classification.

        Args:
            system_data: Latest system telemetry snapshot.
            active_anomalies: List of recent active anomalies.
            suspicious_processes: List of flagged suspicious processes.

        Returns:
            Tuple of (health_score_float, health_status_str).
        """
        score = 100.0

        # 1. CPU Pressure Penalty
        cpu = system_data.get("cpu_percent", 0.0)
        if cpu > 70.0:
            score -= (cpu - 70.0) * 0.8

        # 2. Memory Pressure Penalty
        mem = system_data.get("mem_percent", 0.0)
        if mem > 80.0:
            score -= (mem - 80.0) * 1.0

        # 3. Swap Pressure Penalty
        swap = system_data.get("swap_percent", 0.0)
        if swap > 15.0:
            score -= (swap - 15.0) * 0.5

        # 4. Active Anomaly Penalties (weighted by severity)
        for a in active_anomalies:
            sev = a.get("severity", "low")
            if sev == "high":
                score -= 15.0
            elif sev == "medium":
                score -= 8.0
            else:
                score -= 3.0

        # 5. Suspicious Process Penalties
        score -= len(suspicious_processes) * 10.0

        # Clamp between 0.0 and 100.0
        score = max(0.0, min(100.0, score))

        if score >= 85.0:
            status = "healthy"
        elif score >= 60.0:
            status = "warning"
        else:
            status = "critical"

        return round(score, 1), status
