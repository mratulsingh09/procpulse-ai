# ProcPulse AI — Real-Time Linux Telemetry & Anomaly Profiler

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.141.1-009688.svg)](https://fastapi.tiangolo.com)
[![Scikit-Learn](https://img.shields.io/badge/scikit--learn-1.9.1-F7931E.svg)](https://scikit-learn.org)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

A high-performance, low-overhead Linux system and process telemetry profiler equipped with statistical (EWMA / rolling Z-score) and machine learning (Isolation Forest) anomaly detection engines, connected to a real-time reactive dark-mode web dashboard.

Built for college project reviews (**ITR**), systems engineering labs, and production-grade Linux diagnostics.

---

## Architecture Overview

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
|               |  Telemetry Collector Agent |  (1s tick, self-overhead < 1% CPU)       |
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

## Key Features

1. **Dual Telemetry Collection Layer**:
   - **Direct `/proc` Parsing**: Low-overhead native parsing of `/proc/stat`, `/proc/loadavg`, `/proc/meminfo`, `/proc/diskstats`, `/proc/net/dev`, and `/proc/[pid]/*` (`stat`, `status`, `fd`, `io`, `cmdline`).
   - **Graceful Fallback**: Seamless auxiliary fallback to `psutil` when running on restricted containers, non-root users, or non-Linux development machines.
   - **Self-Overhead Monitoring**: Dedicated measurement of ProcPulse's internal CPU (< 1%) and memory footprint to avoid observer effect.

2. **Statistical & ML Anomaly Engine**:
   - **Rolling EWMA Baseline & Z-Score**: Real-time mean ($\mu$) and variance ($\sigma^2$) tracking with calibrated noise floors for CPU%, RAM%, Disk I/O, and Network traffic.
   - **Multi-Metric Isolation Forest**: High-dimensional outlier detection on vectors (`[CPU, Mem, Disk, Net, Ctxt, Intr]`) with automatic periodic background retraining.
   - **Warm-Up Period**: Configurable initial learning window (default 10s) ensuring zero false alarms during initialization.
   - **Plain-English Root-Cause Diagnostics**: Translates statistical deviations into clear, human-readable explanations pinpointing the exact offending PID, process name, and percentage contribution.

3. **High-Performance SQLite Storage**:
   - Write-Ahead Logging (`PRAGMA journal_mode = WAL`) and `synchronous = NORMAL` for concurrent non-blocking reads/writes.
   - Indexes on timestamps, PIDs, and severity for millisecond query performance.
   - Configurable automatic retention pruner purging data older than the retention window (default 2 hours).

4. **Creative Extras**:
   - **System Health Score (0–100)**: Real-time weighted composite score reflecting hardware pressure, active anomaly severities, and process leaks (classified into *Healthy*, *Warning*, *Critical*).
   - **Process Behavioral Fingerprinting**: Profiles historical CPU, RAM, FD, and thread distributions per executable using Welford's online algorithm.
   - **Suspicious Process & Resource Leak Detector**: Flags rapid file descriptor leaks (e.g. unclosed handles / sockets) and thread explosions.
   - **Executive Incident & CSV Reports**: One-click download of CSV audit trails and print-ready HTML incident summaries.

5. **Single-Page Live Web Dashboard**:
   - Cyberpunk/dark telemetry theme with Chart.js real-time streaming curves (CPU, Load, RAM, Swap, Disk, Net).
   - Searchable, sortable Top Processes table.
   - Live Anomaly Feed with color-coded severity tags and auto-reconnecting WebSocket client.

---

## Project Structure

```
d:\ProcPulse AI — Real-Time Linux Telemetry & Anomaly Profiler\
├── main.py                     # Root launcher
├── simulate_anomaly.py         # Safe synthetic anomaly injector for demo reviews
├── requirements.txt            # Pinned dependencies
├── PLAN.md                     # Architecture specification & roadmap
├── README.md                   # Complete documentation
├── procpulse/
│   ├── __init__.py
│   ├── config.py               # Pydantic Settings configuration
│   ├── app.py                  # FastAPI application factory & static mounting
│   ├── main.py                 # Telemetry loop & Uvicorn runner
│   ├── collector/
│   │   ├── __init__.py
│   │   ├── proc_parser.py      # Direct Linux /proc virtual filesystem parser
│   │   ├── system.py           # System-wide telemetry collector
│   │   └── process.py          # Per-process scanner & top-N tracker
│   ├── storage/
│   │   ├── __init__.py
│   │   ├── models.py           # Pydantic data schemas
│   │   └── database.py         # SQLite WAL connection manager & retention pruner
│   ├── engine/
│   │   ├── __init__.py
│   │   ├── zscore.py           # Rolling EWMA and Z-score statistical detector
│   │   ├── isolation_forest.py # Scikit-learn multi-metric Isolation Forest
│   │   ├── health_score.py     # System Health Score calculator (0-100)
│   │   ├── fingerprint.py      # Process behavioral fingerprinting
│   │   ├── suspicious.py       # Suspicious FD leak & thread explosion detector
│   │   └── detector.py         # Unified anomaly coordinator & root-cause formatter
│   ├── api/
│   │   ├── __init__.py
│   │   ├── routes.py           # REST endpoints & report generators
│   │   └── websocket.py        # Real-time WebSocket connection manager
│   └── dashboard/
│       ├── index.html          # Responsive single-page dashboard
│       ├── style.css           # Modern dark-theme telemetry stylesheet
│       └── app.js              # Vanilla JS Chart.js engine & WebSocket client
└── tests/
    ├── __init__.py
    ├── conftest.py             # Realistic mock /proc fixtures
    ├── test_collector.py       # Tests for /proc parser, system & process collection
    ├── test_storage.py         # Tests for SQLite models, queries, and retention
    ├── test_engine.py          # Tests for Z-score, IsolationForest, and detectors
    └── test_api.py             # Tests for FastAPI REST & WebSocket endpoints
```

---

## Installation & Quickstart

### Prerequisites
- Python 3.11+
- Linux (Debian, Ubuntu, Fedora, Arch, Alpine, etc.) or Windows / macOS for development

### Setup Steps

1. **Clone or enter the project directory**:
   ```bash
   cd "ProcPulse AI — Real-Time Linux Telemetry & Anomaly Profiler"
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python -m venv venv
   # On Linux/macOS:
   source venv/bin/activate
   # On Windows:
   .\venv\Scripts\Activate.ps1
   ```

3. **Install pinned dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the application**:
   ```bash
   python main.py
   ```

5. **Open the live dashboard**:
   Navigate to [http://localhost:8000](http://localhost:8000) (or `http://127.0.0.1:8000`).

---

## Running the Automated Test Suite

Run the full pytest suite covering all collectors, SQLite storage, mathematical detectors, and REST/WebSocket endpoints:

```bash
python -m pytest tests/ -v
```

All 24 automated unit and integration tests will execute and validate the system components.

---

## How the Machine Learning & Anomaly Detection Works

### 1. Rolling EWMA Baseline & Z-Score
For rapidly evolving individual metrics ($x_t$), ProcPulse maintains an Exponentially Weighted Moving Average ($\mu_t$) and Exponentially Weighted Moving Variance ($\sigma_t^2$):

$$\mu_t = \alpha x_t + (1 - \alpha) \mu_{t-1}$$
$$\sigma_t^2 = (1 - \alpha) (\sigma_{t-1}^2 + \alpha (x_t - \mu_{t-1})^2)$$

Before updating the baseline, the instantaneous observation $x_t$ is evaluated against the prior baseline:

$$Z = \frac{x_t - \mu_{prior}}{\max(\sigma_{prior}, \sigma_{floor})}$$

- **Low Severity**: $Z \ge 2.5$
- **Medium Severity**: $Z \ge 3.5$
- **High Severity**: $Z \ge 4.5$

The calibrated $\sigma_{floor}$ prevents false positives when an idle system transitions from 0.1% to 1.0% CPU.

### 2. Multi-Metric Isolation Forest
Single-metric thresholds can miss coordinated multi-variate anomalies (e.g. moderate CPU rise combined with abnormal context-switch proliferation and anomalous network socket activity).

ProcPulse samples a 6-dimensional feature vector:
$$\vec{v} = [ \text{CPU}\%, \text{Mem}\%, \ln(\text{DiskIO} + 1), \ln(\text{NetIO} + 1), \text{CtxtSwitches/s}, \text{Interrupts/s} ]$$

A background scikit-learn `IsolationForest(contamination=0.03)` builds an ensemble of isolation trees. Outliers with short average path lengths yield negative decision function values. ProcPulse automatically identifies the dominant contributing dimension using standardized z-scores against the training centroid.

### 3. Root-Cause Process Attribution
When an anomaly is flagged, the engine correlates system-level pressure with concurrent per-process metrics, identifying the primary culprit and generating human-readable diagnostics:

> *"CPU utilization surged to 92.4% (4.2σ above baseline of 18.1%), caused mainly by PID 1420 ('python.exe') consuming 85.0% CPU."*

---

## Live Demonstration Guide (College ITR Review)

Use `simulate_anomaly.py` to trigger safe, controlled, auto-cleaning anomalies live in front of reviewers:

```bash
# 1. Trigger a CPU Surge (runs mathematical burn threads for 10s, then cools down)
python simulate_anomaly.py --cpu --duration 10

# 2. Trigger a Memory Spike (allocates 500MB RAM, holds 10s, then garbage-collects)
python simulate_anomaly.py --memory --memory-mb 500 --duration 10

# 3. Trigger a Disk I/O Burst (burst read/writes in tempfile, syncs, then unlinks)
python simulate_anomaly.py --io --duration 10

# 4. Trigger Suspicious File Descriptor Leak (opens 60 descriptors rapidly, triggers alert, then closes all)
python simulate_anomaly.py --fd --count 60 --duration 10

# 5. Run the complete automated multi-phase demonstration sequence
python simulate_anomaly.py --all
```

All simulated scenarios safely clean up their temporary files, allocated memory, and file descriptors immediately upon completion or user interrupt (`Ctrl+C`).

---

## REST & WebSocket API Contract

| Endpoint | Method | Description |
|---|---|---|
| `GET /` | HTML | Live telemetry dashboard interface |
| `GET /api/health` | JSON | Overall health score (0-100), status, agent uptime, and self-overhead |
| `GET /api/metrics` | JSON | Time-series historical metrics (`?limit=60&since=<timestamp>`) |
| `GET /api/processes` | JSON | Top active processes sorted by CPU and memory consumption |
| `GET /api/anomalies` | JSON | Detected anomaly events (`?severity=high&limit=50`) |
| `GET /api/suspicious` | JSON | Active suspicious process alerts (FD leaks, thread explosions) |
| `GET /api/reports/export.csv` | CSV | Downloadable CSV audit log of anomalies and telemetry |
| `GET /api/reports/incident` | HTML | Printable executive incident report with timeline and stats |
| `WS /ws/live` | WebSocket | 1-second real-time telemetry push stream |

---

## System Health Score Breakdown

The composite Health Score ($H \in [0, 100]$) dynamically reflects overall infrastructure health:
- **Base Score**: 100.0
- **CPU Penalty**: If CPU > 70%, $-0.8 \times (\text{CPU} - 70)$
- **Memory Penalty**: If RAM > 80%, $-1.0 \times (\text{RAM} - 80)$
- **Swap Penalty**: If Swap > 15%, $-0.5 \times (\text{Swap} - 15)$
- **Active Anomalies**: $-15$ (High), $-8$ (Medium), $-3$ (Low)
- **Suspicious Processes**: $-10$ per detected leak

---

## Limitations & Future Scope

### Known Limitations
1. **Direct `/proc` Requirements**: Direct `/proc` parsing requires a Linux kernel. On non-Linux host OSes (such as macOS or Windows development workstations), ProcPulse falls back to `psutil`.
2. **Permission Boundaries**: Reading `/proc/[pid]/fd` and `/proc/[pid]/io` for processes owned by other users requires root or `CAP_SYS_PTRACE` capabilities. ProcPulse handles permission denials gracefully without crashing.

### Future Scope
1. **eBPF Kernel Probing**: Integrate BCC / libbpf probes to capture microsecond-level syscall latency spikes and block I/O queuing without polling overhead.
2. **Alert Webhook Integrations**: Push immediate incident notifications directly to Slack, Microsoft Teams, or PagerDuty.
3. **Multi-Node Cluster Aggregation**: Centralize telemetry from distributed nodes into an enterprise time-series cluster.
