"""Integration tests for FastAPI REST routes and WebSocket."""

import socket
from pathlib import Path
from starlette.testclient import TestClient

from procpulse.app import create_app
from procpulse.config import Settings, find_available_port
from procpulse.storage.database import Database


def test_api_endpoints(tmp_path: Path):
    """Test REST API endpoints."""
    db = Database(str(tmp_path / "test_api.db"))

    # Seed mock metric
    db.insert_system_metric({
        "timestamp": 1000.0,
        "cpu_percent": 15.0,
        "cpu_per_core": [15.0],
        "load_1m": 0.2,
        "load_5m": 0.1,
        "load_15m": 0.1,
        "mem_used": 1000,
        "mem_total": 4000,
        "mem_percent": 25.0,
        "swap_used": 0,
        "swap_total": 1000,
        "swap_percent": 0.0,
        "disk_read_bytes_sec": 100.0,
        "disk_write_bytes_sec": 200.0,
        "net_recv_bytes_sec": 300.0,
        "net_sent_bytes_sec": 400.0,
        "ctx_switches_sec": 500.0,
        "interrupts_sec": 600.0,
    })

    # Seed mock anomaly
    db.insert_anomaly({
        "timestamp": 1000.0,
        "metric": "cpu",
        "severity": "high",
        "score": 0.98,
        "value": 95.0,
        "baseline": 15.0,
        "z_score": 4.5,
        "related_pid": 1234,
        "related_process": "python",
        "explanation": "CPU 4.5σ above baseline",
    })

    app = create_app(db=db)
    client = TestClient(app)

    # 1. Test root dashboard
    resp = client.get("/")
    assert resp.status_code == 200

    # 2. Test /api/health
    resp = client.get("/api/health")
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert "health_score" in data
    assert "overhead" in data

    # 3. Test /api/metrics
    resp = client.get("/api/metrics?limit=5")
    assert resp.status_code == 200
    metrics = resp.json()
    assert len(metrics) == 1
    assert metrics[0]["cpu_percent"] == 15.0

    # 4. Test /api/processes
    resp = client.get("/api/processes")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # 5. Test /api/anomalies
    resp = client.get("/api/anomalies")
    assert resp.status_code == 200
    anoms = resp.json()
    assert len(anoms) == 1
    assert anoms[0]["severity"] == "high"

    # 6. Test CSV Export
    resp = client.get("/api/reports/export.csv")
    assert resp.status_code == 200
    assert "text/csv" in resp.headers["content-type"]
    assert "Timestamp,Metric,Severity" in resp.text

    # 7. Test Incident Report HTML
    resp = client.get("/api/reports/incident")
    assert resp.status_code == 200
    assert "text/html" in resp.headers["content-type"]
    assert "ProcPulse AI — Incident &amp; Telemetry Audit Report" in resp.text or "ProcPulse AI" in resp.text


def test_websocket_live(tmp_path: Path):
    """Test WebSocket connection and ping."""
    db = Database(str(tmp_path / "test_ws.db"))
    app = create_app(db=db)
    client = TestClient(app)

    with client.websocket_connect("/ws/live") as websocket:
        websocket.send_text("ping")
        data = websocket.receive_text()
        assert data == "pong"


def test_settings_port_env_override(monkeypatch):
    """The configured port should honor the environment override."""
    monkeypatch.setenv("PROCPULSE_PORT", "8123")
    settings = Settings()
    assert settings.port == 8123


def test_find_available_port_skips_busy_port():
    """When a preferred port is already bound, pick the next available one."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as busy:
        busy.bind(("127.0.0.1", 0))
        preferred_port = busy.getsockname()[1]

        chosen_port = find_available_port(preferred_port, "127.0.0.1")
        assert chosen_port != preferred_port
        assert chosen_port >= preferred_port
