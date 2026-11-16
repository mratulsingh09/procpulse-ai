"""Unit tests for the Anomaly Engine and detectors."""

import time
from procpulse.engine.zscore import RollingEWMA, ZScoreDetector
from procpulse.engine.isolation_forest import MultiMetricIsolationForest
from procpulse.engine.health_score import HealthScoreCalculator
from procpulse.engine.fingerprint import ProcessFingerprinter
from procpulse.engine.suspicious import SuspiciousProcessDetector
from procpulse.engine.detector import AnomalyEngine


def test_rolling_ewma():
    """Test EWMA calculation and Z-score derivation."""
    ewma = RollingEWMA(alpha=0.2, min_std=1.0)

    # Feed consistent low values
    for _ in range(20):
        ewma.update(10.0)

    assert abs(ewma.mean - 10.0) < 0.1

    # Sudden high value creates positive Z-score
    mean, std, z = ewma.update(50.0)
    assert z > 3.0


def test_zscore_detector_thresholds():
    """Test ZScoreDetector classification of low, medium, and high anomalies."""
    detector = ZScoreDetector(alpha=0.2, low_threshold=2.5, med_threshold=3.5, high_threshold=4.5)

    # Establish baseline around 15.0
    for _ in range(30):
        detector.check("cpu_percent", 15.0)

    # Normal observation
    assert detector.check("cpu_percent", 16.0) is None

    # Medium spike
    med_res = detector.check("cpu_percent", 45.0)
    assert med_res is not None
    assert med_res["severity"] in ("medium", "high")

    # High spike
    high_res = detector.check("cpu_percent", 98.0)
    assert high_res is not None
    assert high_res["severity"] == "high"


def test_isolation_forest_detector():
    """Test MultiMetricIsolationForest training and anomaly scoring."""
    detector = MultiMetricIsolationForest(contamination=0.05, history_size=100, retrain_interval_sec=0)

    # Feed 35 normal telemetry samples
    for _ in range(35):
        sample = {
            "cpu_percent": 10.0,
            "mem_percent": 25.0,
            "disk_read_bytes_sec": 1000.0,
            "disk_write_bytes_sec": 2000.0,
            "net_recv_bytes_sec": 5000.0,
            "net_sent_bytes_sec": 1000.0,
            "ctx_switches_sec": 500.0,
            "interrupts_sec": 200.0,
        }
        detector.add_sample(sample)

    assert detector.train() is True
    assert detector.model is not None

    # An extreme multi-metric anomaly (CPU 99%, mem 95%, disk 500MB/s)
    extreme_sample = {
        "cpu_percent": 99.0,
        "mem_percent": 95.0,
        "disk_read_bytes_sec": 500000000.0,
        "disk_write_bytes_sec": 500000000.0,
        "net_recv_bytes_sec": 500000000.0,
        "net_sent_bytes_sec": 500000000.0,
        "ctx_switches_sec": 50000.0,
        "interrupts_sec": 25000.0,
    }
    anom = detector.predict(extreme_sample)
    assert anom is not None
    assert anom["metric"] == "multi_metric_cluster"


def test_health_score_calculator():
    """Test health score decreases under CPU, memory, and anomaly load."""
    calc = HealthScoreCalculator()

    # Normal system
    score_normal, status_normal = calc.calculate(
        system_data={"cpu_percent": 15.0, "mem_percent": 40.0, "swap_percent": 0.0},
        active_anomalies=[],
        suspicious_processes=[],
    )
    assert score_normal == 100.0
    assert status_normal == "healthy"

    # Heavily loaded system with high anomaly
    score_stressed, status_stressed = calc.calculate(
        system_data={"cpu_percent": 95.0, "mem_percent": 92.0, "swap_percent": 40.0},
        active_anomalies=[{"severity": "high"}, {"severity": "medium"}],
        suspicious_processes=[{"pid": 999}],
    )
    assert score_stressed < 60.0
    assert status_stressed == "critical"


def test_process_fingerprinting():
    """Test online process fingerprinting with Welford's algorithm."""
    fp = ProcessFingerprinter()
    procs = [
        {"name": "nginx", "cpu_percent": 5.0, "memory_rss": 50000000, "num_fds": 10, "num_threads": 2},
        {"name": "nginx", "cpu_percent": 7.0, "memory_rss": 52000000, "num_fds": 12, "num_threads": 2},
    ]
    fp.update(procs)
    prof = fp.get_fingerprint("nginx")
    assert prof is not None
    assert prof["sample_count"] == 2
    assert prof["mean_cpu"] == 6.0


def test_suspicious_process_fd_leak():
    """Test SuspiciousProcessDetector flags rapid file descriptor leak."""
    detector = SuspiciousProcessDetector()

    # Initial state
    detector.check([{"pid": 4001, "name": "leaky_app", "num_fds": 10, "num_threads": 2}])

    # Rapid FD leak: jumps to 60 open FDs
    alerts = detector.check([{"pid": 4001, "name": "leaky_app", "num_fds": 60, "num_threads": 2}])
    assert len(alerts) == 1
    assert alerts[0]["type"] == "fd_leak"
    assert alerts[0]["pid"] == 4001


def test_anomaly_engine_warmup_and_detection():
    """Test AnomalyEngine suppresses alerts during warm-up and triggers afterwards."""
    engine = AnomalyEngine(warmup_samples=5)
    sample_system = {
        "timestamp": 1000.0,
        "cpu_percent": 10.0,
        "mem_percent": 20.0,
        "disk_read_bytes_sec": 1000.0,
        "disk_write_bytes_sec": 1000.0,
        "net_recv_bytes_sec": 1000.0,
        "net_sent_bytes_sec": 1000.0,
        "ctx_switches_sec": 100.0,
        "interrupts_sec": 50.0,
    }
    sample_procs = [
        {"pid": 111, "name": "python", "cpu_percent": 5.0, "memory_percent": 2.0, "num_fds": 5, "num_threads": 1}
    ]

    # Warm-up ticks
    for i in range(5):
        anoms = engine.process_tick(sample_system, sample_procs)
        assert len(anoms) == 0

    assert engine.is_warmed_up is True

    # After warm-up, inject massive CPU spike
    spike_system = dict(sample_system)
    spike_system["cpu_percent"] = 96.0
    spike_procs = [
        {"pid": 111, "name": "python", "cpu_percent": 90.0, "memory_percent": 2.0, "num_fds": 5, "num_threads": 1}
    ]
    anomalies = engine.process_tick(spike_system, spike_procs)
    assert len(anomalies) > 0
    cpu_alert = anomalies[0]
    assert cpu_alert["metric"] == "cpu_percent"
    assert cpu_alert["related_pid"] == 111
    assert "PID 111 ('python')" in cpu_alert["explanation"]
