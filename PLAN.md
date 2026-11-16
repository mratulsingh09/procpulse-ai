# ProcPulse AI — Implementation Plan
**Real-Time Linux Telemetry & Anomaly Profiler**

---

## 1. System Architecture

```
+---------------------------------------------------------------------------------------+
|                                    PROCPULSE AI                                       |
+---------------------------------------------------------------------------------------+
|                                                                                       |
|  +--------------------+         +-----------------------+                             |
|  |   Linux /proc      |         |  psutil Cross-Platform|                             |
|  |   Direct Parser    |         |  Fallback & Auxiliary |                             |
|  +---------+----------+         +-----------+-----------+                             |
|            |                                |                                         |
|            +---------------+----------------+                                         |
|                            v                                                          |
|               +----------------------------+                                          |
|               |  Telemetry Collector Agent |  (1s configurable loop, < 3% CPU self)   |
|               +--------------+-------------+                                          |
|                              |                                                        |
|         +--------------------+--------------------+                                   |
|         v                                         v                                   |
|  +---------------+                     +--------------------+                         |
|  | Storage Layer |                     |   Anomaly Engine   |                         |
|  | SQLite (WAL)  |                     |  - Rolling Z-Score |                         |
|  | Auto-Purge    |                     |  - EWMA Baseline   |                         |
|  +---------------+                     |  - IsolationForest |                         |
|                                        |  - Health Score    |                         |
|                                        |  - Process Profiles|                         |
|                                        +----------+---------+                         |
|                                                   |                                   |
|                                                   v                                   |
|                              +----------------------------+                           |
|                              |      FastAPI Backend       |                           |
|                              |  REST APIs + WebSocket WS  |                           |
|                              +--------------+-------------+                           |
|                                             |                                         |
|                                             v                                         |
|                              +----------------------------+                           |
|                              |   Single-Page Dashboard    |                           |
|                              |  Vanilla JS + Chart.js     |                           |
|                              |  Dark Telemetry UI         |                           |
|                              +----------------------------+                           |
+---------------------------------------------------------------------------------------+
```

---

## 2. Directory & File Structure

```
d:\ProcPulse AI — Real-Time Linux Telemetry & Anomaly Profiler\
├── PLAN.md                     # Architecture, specifications, and roadmap
├── requirements.txt            # Pinned dependencies
├── main.py                     # Root launcher
├── simulate_anomaly.py         # Safe synthetic anomaly injector
├── README.md                   # Full documentation, setup, architecture, ML explanation
├── procpulse/
│   ├── __init__.py             # Package init
│   ├── config.py               # Centralized configuration & environment settings
│   ├── collector/
│   │   ├── __init__.py
│   │   ├── proc_parser.py      # Direct Linux /proc filesystem parser
│   │   ├── system.py           # System-level telemetry collector
│   │   └── process.py          # Process-level telemetry collector
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── database.py         # SQLite connection manager, WAL mode, migrations
│   │   └── models.py           # Dataclasses & table schemas
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── zscore.py           # Rolling Z-score and EWMA baseline detector
│   │   ├── isolation_forest.py # Periodic retraining multi-metric Isolation Forest
│   │   ├── health_score.py     # System Health Score calculator (0-100)
│   │   ├── fingerprint.py      # Process behavioral fingerprinting
│   │   ├── suspicious.py       # Suspicious process & sudden fd/thread leak detector
│   │   └── detector.py         # Unified anomaly coordinator with warm-up logic
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py           # REST endpoints (/api/metrics, /processes, /anomalies, etc.)
│   │   └── websocket.py        # /ws/live real-time broadcaster
│   └── dashboard/
│       ├── index.html          # Single-page telemetry dashboard
│       ├── style.css           # Modern dark-theme telemetry stylesheet
│       └── app.js              # Vanilla JS frontend with Chart.js streaming & reconnect
└── tests/
    ├── __init__.py
    ├── conftest.py             # Fixtures and mock data
    ├── test_collector.py       # Tests for /proc parser, system & process collection
    ├── test_storage.py         # Tests for DB schema, inserts, queries, retention prune
    ├── test_engine.py          # Tests for Z-score, IsolationForest, health score, detector
    └── test_api.py             # Tests for FastAPI REST endpoints & WebSocket
```

---

## 3. Data Schema (SQLite)

### Table: `system_metrics`
- `id`: INTEGER PRIMARY KEY AUTOINCREMENT
- `timestamp`: REAL NOT NULL (indexed)
- `cpu_percent`: REAL NOT NULL
- `cpu_per_core`: TEXT NOT NULL (JSON array of float values)
- `load_1m`: REAL NOT NULL
- `load_5m`: REAL NOT NULL
- `load_15m`: REAL NOT NULL
- `mem_used`: INTEGER NOT NULL
- `mem_total`: INTEGER NOT NULL
- `mem_percent`: REAL NOT NULL
- `swap_used`: INTEGER NOT NULL
- `swap_total`: INTEGER NOT NULL
- `swap_percent`: REAL NOT NULL
- `disk_read_bytes_sec`: REAL NOT NULL
- `disk_write_bytes_sec`: REAL NOT NULL
- `net_recv_bytes_sec`: REAL NOT NULL
- `net_sent_bytes_sec`: REAL NOT NULL
- `ctx_switches_sec`: REAL NOT NULL
- `interrupts_sec`: REAL NOT NULL
- `cpu_temp`: REAL (nullable)
- `proc_pulse_cpu`: REAL NOT NULL (self-monitoring)
- `proc_pulse_mem_rss`: INTEGER NOT NULL (self-monitoring)

### Table: `process_metrics`
- `id`: INTEGER PRIMARY KEY AUTOINCREMENT
- `timestamp`: REAL NOT NULL (indexed)
- `pid`: INTEGER NOT NULL (indexed)
- `name`: TEXT NOT NULL
- `cmdline`: TEXT
- `cpu_percent`: REAL NOT NULL
- `memory_rss`: INTEGER NOT NULL
- `memory_percent`: REAL NOT NULL
- `num_threads`: INTEGER NOT NULL
- `num_fds`: INTEGER NOT NULL
- `state`: TEXT NOT NULL
- `io_read_bytes`: INTEGER NOT NULL
- `io_write_bytes`: INTEGER NOT NULL

### Table: `anomalies`
- `id`: INTEGER PRIMARY KEY AUTOINCREMENT
- `timestamp`: REAL NOT NULL (indexed)
- `metric`: TEXT NOT NULL
- `severity`: TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high'))
- `score`: REAL NOT NULL
- `value`: REAL NOT NULL
- `baseline`: REAL NOT NULL
- `z_score`: REAL NOT NULL
- `related_pid`: INTEGER (nullable)
- `related_process`: TEXT (nullable)
- `explanation`: TEXT NOT NULL

### Table: `process_fingerprints`
- `name`: TEXT PRIMARY KEY
- `sample_count`: INTEGER NOT NULL
- `mean_cpu`: REAL NOT NULL
- `std_cpu`: REAL NOT NULL
- `mean_mem`: REAL NOT NULL
- `std_mem`: REAL NOT NULL
- `mean_fds`: REAL NOT NULL
- `std_fds`: REAL NOT NULL
- `mean_threads`: REAL NOT NULL
- `std_threads`: REAL NOT NULL
- `last_updated`: REAL NOT NULL

---

## 4. API Contract

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/health` | Overall system health score (0-100), status, agent uptime, self-overhead |
| `GET` | `/api/metrics` | Time-series system metrics (`limit`, `window_seconds`) |
| `GET` | `/api/processes` | Current top processes with state, FDs, threads, fingerprint status |
| `GET` | `/api/anomalies` | Detected anomaly records (`severity`, `limit`, `since`) |
| `GET` | `/api/suspicious` | Active suspicious process alerts (e.g. FD / thread leaks) |
| `GET` | `/api/reports/export.csv` | Export anomalies and system telemetry as downloadable CSV |
| `GET` | `/api/reports/incident` | Formatted printable incident summary report |
| `WS` | `/ws/live` | WebSocket 1Hz stream: system metrics, top procs, active alerts, health score |

---

## 5. Build Order & Verification Milestones

1. **Milestone 1 — Collector**: Direct `/proc` parser + psutil system/process telemetry + self-monitoring. Unit tests with Linux `/proc` fixtures. Run pytest.
2. **Milestone 2 — Storage**: SQLite database manager with WAL mode, indexing, models, batch inserts, and retention auto-pruning. Unit tests. Run pytest.
3. **Milestone 3 — Anomaly Engine**: Rolling Z-score/EWMA, warm-up period, IsolationForest multi-metric detector, System Health Score, process fingerprinting, and suspicious process detection. Unit tests. Run pytest.
4. **Milestone 4 — API & WebSocket**: FastAPI routes, Pydantic schemas, WebSocket broadcaster, background collector/engine loop. Integration tests with TestClient. Run pytest.
5. **Milestone 5 — Dashboard**: Single-page modern dark-theme UI with Chart.js live charts, top process explorer, anomaly feed, auto-reconnect, health score gauge. Verify browser rendering.
6. **Milestone 6 — Demo Mode**: `simulate_anomaly.py` CLI supporting `--cpu`, `--memory`, `--io`, `--fd`, `--all` with guaranteed clean-up. Verify anomaly trigger and dashboard detection.
7. **Milestone 7 — Creative Extras & Verification**: Health score calibration, suspicious process detection, CSV/incident report export, CPU overhead benchmark (< 3%). Run all tests and 5-min continuous test.
8. **Milestone 8 — Documentation & Deliverables**: Comprehensive `README.md`, setup guide, architecture diagrams, college ITR presentation notes.
