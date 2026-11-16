"""Unit tests for the SQLite storage layer."""

import time
from pathlib import Path
from procpulse.storage.database import Database


def test_database_initialization(tmp_path: Path):
    """Test that SQLite database initializes with WAL mode and tables."""
    db_file = tmp_path / "test_procpulse.db"
    db = Database(str(db_file))
    assert db_file.exists()


def test_system_metrics_insert_and_query(tmp_path: Path):
    """Test inserting and querying system metrics."""
    db = Database(str(tmp_path / "test.db"))
    now = time.time()

    sample = {
        "timestamp": now,
        "cpu_percent": 34.5,
        "cpu_per_core": [30.0, 39.0],
        "load_1m": 0.55,
        "load_5m": 0.40,
        "load_15m": 0.30,
        "mem_used": 4000000,
        "mem_total": 8000000,
        "mem_percent": 50.0,
        "swap_used": 100000,
        "swap_total": 2000000,
        "swap_percent": 5.0,
        "disk_read_bytes_sec": 102400.0,
        "disk_write_bytes_sec": 204800.0,
        "net_recv_bytes_sec": 51200.0,
        "net_sent_bytes_sec": 25600.0,
        "ctx_switches_sec": 1500.0,
        "interrupts_sec": 800.0,
        "cpu_temp": 45.2,
        "proc_pulse_cpu": 0.8,
        "proc_pulse_mem_rss": 35000000,
    }

    row_id = db.insert_system_metric(sample)
    assert row_id > 0

    metrics = db.get_system_metrics(limit=10)
    assert len(metrics) == 1
    m = metrics[0]
    assert m["cpu_percent"] == 34.5
    assert m["cpu_per_core"] == [30.0, 39.0]
    assert m["mem_percent"] == 50.0
    assert m["cpu_temp"] == 45.2


def test_process_metrics_insert_and_query(tmp_path: Path):
    """Test batch inserting and querying process metrics."""
    db = Database(str(tmp_path / "test.db"))
    now = time.time()

    procs = [
        {
            "timestamp": now,
            "pid": 101,
            "name": "python",
            "cmdline": "python app.py",
            "cpu_percent": 25.0,
            "memory_rss": 104857600,
            "memory_percent": 5.2,
            "num_threads": 4,
            "num_fds": 18,
            "state": "running",
            "io_read_bytes": 1000,
            "io_write_bytes": 2000,
        },
        {
            "timestamp": now,
            "pid": 102,
            "name": "chrome",
            "cmdline": "chrome --browser",
            "cpu_percent": 12.0,
            "memory_rss": 524288000,
            "memory_percent": 15.0,
            "num_threads": 16,
            "num_fds": 42,
            "state": "sleeping",
            "io_read_bytes": 5000,
            "io_write_bytes": 10000,
        },
    ]

    count = db.insert_process_metrics(procs)
    assert count == 2

    recent = db.get_recent_processes(limit=10)
    assert len(recent) == 2
    # python had 25.0% CPU so it should be first
    assert recent[0]["pid"] == 101
    assert recent[0]["name"] == "python"


def test_anomalies_insert_and_filter(tmp_path: Path):
    """Test inserting anomaly records and filtering by severity."""
    db = Database(str(tmp_path / "test.db"))
    now = time.time()

    a1 = {
        "timestamp": now - 10,
        "metric": "cpu",
        "severity": "high",
        "score": 0.95,
        "value": 98.2,
        "baseline": 15.0,
        "z_score": 4.8,
        "related_pid": 555,
        "related_process": "stress-ng",
        "explanation": "CPU 4.8σ above baseline caused by PID 555 stress-ng",
    }
    a2 = {
        "timestamp": now,
        "metric": "memory",
        "severity": "low",
        "score": 0.60,
        "value": 72.0,
        "baseline": 55.0,
        "z_score": 2.6,
        "related_pid": None,
        "related_process": None,
        "explanation": "Memory 2.6σ above baseline",
    }

    db.insert_anomaly(a1)
    db.insert_anomaly(a2)

    all_anoms = db.get_anomalies(limit=10)
    assert len(all_anoms) == 2

    high_anoms = db.get_anomalies(limit=10, severity="high")
    assert len(high_anoms) == 1
    assert high_anoms[0]["metric"] == "cpu"
    assert high_anoms[0]["related_pid"] == 555


def test_fingerprint_upsert(tmp_path: Path):
    """Test upserting and retrieving process baseline fingerprints."""
    db = Database(str(tmp_path / "test.db"))
    fp1 = {
        "name": "nginx",
        "sample_count": 10,
        "mean_cpu": 2.5,
        "std_cpu": 0.5,
        "mean_mem": 20480000.0,
        "std_mem": 1024000.0,
        "mean_fds": 12.0,
        "std_fds": 1.0,
        "mean_threads": 2.0,
        "std_threads": 0.0,
        "last_updated": time.time(),
    }
    db.upsert_fingerprint(fp1)

    fps = db.get_fingerprints()
    assert "nginx" in fps
    assert fps["nginx"]["sample_count"] == 10

    # Update with more samples
    fp1["sample_count"] = 50
    fp1["mean_cpu"] = 3.0
    db.upsert_fingerprint(fp1)

    fps2 = db.get_fingerprints()
    assert fps2["nginx"]["sample_count"] == 50
    assert fps2["nginx"]["mean_cpu"] == 3.0


def test_retention_purge(tmp_path: Path):
    """Test purging records older than retention cutoff."""
    db = Database(str(tmp_path / "test.db"))
    old_time = time.time() - 10000.0  # ~2.7 hours ago
    now = time.time()

    # Insert old records
    db.insert_system_metric({
        "timestamp": old_time,
        "cpu_percent": 10.0,
        "cpu_per_core": [10.0],
        "load_1m": 0.1,
        "load_5m": 0.1,
        "load_15m": 0.1,
        "mem_used": 1000,
        "mem_total": 2000,
        "mem_percent": 50.0,
        "swap_used": 0,
        "swap_total": 1000,
        "swap_percent": 0.0,
        "disk_read_bytes_sec": 0.0,
        "disk_write_bytes_sec": 0.0,
        "net_recv_bytes_sec": 0.0,
        "net_sent_bytes_sec": 0.0,
        "ctx_switches_sec": 0.0,
        "interrupts_sec": 0.0,
    })

    # Insert fresh record
    db.insert_system_metric({
        "timestamp": now,
        "cpu_percent": 20.0,
        "cpu_per_core": [20.0],
        "load_1m": 0.2,
        "load_5m": 0.2,
        "load_15m": 0.2,
        "mem_used": 1000,
        "mem_total": 2000,
        "mem_percent": 50.0,
        "swap_used": 0,
        "swap_total": 1000,
        "swap_percent": 0.0,
        "disk_read_bytes_sec": 0.0,
        "disk_write_bytes_sec": 0.0,
        "net_recv_bytes_sec": 0.0,
        "net_sent_bytes_sec": 0.0,
        "ctx_switches_sec": 0.0,
        "interrupts_sec": 0.0,
    })

    # Purge older than 3600 seconds (1 hour)
    deleted = db.purge_old_records(retention_seconds=3600.0)
    assert deleted >= 1

    remaining = db.get_system_metrics(limit=10)
    assert len(remaining) == 1
    assert remaining[0]["cpu_percent"] == 20.0
