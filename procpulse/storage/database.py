"""SQLite storage manager with WAL mode, indexing, and retention auto-pruning."""

import json
import sqlite3
import threading
import logging
import time
from pathlib import Path
from typing import Dict, List, Any, Optional

from procpulse.config import settings

logger = logging.getLogger(__name__)


class Database:
    """Manages SQLite database connections, schemas, transactions, and retention."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        """Initialize database manager.

        Args:
            db_path: Path to SQLite database file (defaults to settings.db_path).
                     Use ':memory:' for an ephemeral in-process shared connection.
        """
        self.db_path = Path(db_path or settings.db_path)
        self._lock = threading.Lock()
        self._shared_conn: Optional[sqlite3.Connection] = None

        if str(self.db_path) == ":memory:":
            # For in-memory databases, keep a single persistent connection shared across threads
            self._shared_conn = sqlite3.connect(":memory:", check_same_thread=False)
            self._shared_conn.row_factory = sqlite3.Row
            self._shared_conn.execute("PRAGMA journal_mode = WAL;")
            self._shared_conn.execute("PRAGMA synchronous = NORMAL;")
        else:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)

        self._init_schema()

    def _get_connection(self) -> sqlite3.Connection:
        """Create and configure a new SQLite connection with WAL mode."""
        if self._shared_conn is not None:
            return self._shared_conn
        conn = sqlite3.connect(str(self.db_path), timeout=10.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode = WAL;")
        conn.execute("PRAGMA synchronous = NORMAL;")
        conn.execute("PRAGMA busy_timeout = 5000;")
        return conn

    def _init_schema(self) -> None:
        """Initialize required database tables and performance indexes."""
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()

            # 1. System Metrics Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS system_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                cpu_percent REAL NOT NULL,
                cpu_per_core TEXT NOT NULL,
                load_1m REAL NOT NULL,
                load_5m REAL NOT NULL,
                load_15m REAL NOT NULL,
                mem_used INTEGER NOT NULL,
                mem_total INTEGER NOT NULL,
                mem_percent REAL NOT NULL,
                swap_used INTEGER NOT NULL,
                swap_total INTEGER NOT NULL,
                swap_percent REAL NOT NULL,
                disk_read_bytes_sec REAL NOT NULL,
                disk_write_bytes_sec REAL NOT NULL,
                net_recv_bytes_sec REAL NOT NULL,
                net_sent_bytes_sec REAL NOT NULL,
                ctx_switches_sec REAL NOT NULL,
                interrupts_sec REAL NOT NULL,
                cpu_temp REAL,
                proc_pulse_cpu REAL NOT NULL DEFAULT 0.0,
                proc_pulse_mem_rss INTEGER NOT NULL DEFAULT 0
            );
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_sys_time ON system_metrics (timestamp);"
            )

            # 2. Process Metrics Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS process_metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                pid INTEGER NOT NULL,
                name TEXT NOT NULL,
                cmdline TEXT,
                cpu_percent REAL NOT NULL,
                memory_rss INTEGER NOT NULL,
                memory_percent REAL NOT NULL,
                num_threads INTEGER NOT NULL,
                num_fds INTEGER NOT NULL DEFAULT 0,
                state TEXT NOT NULL DEFAULT 'running',
                io_read_bytes INTEGER NOT NULL DEFAULT 0,
                io_write_bytes INTEGER NOT NULL DEFAULT 0
            );
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_proc_time ON process_metrics (timestamp);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_proc_pid ON process_metrics (pid);"
            )

            # 3. Anomalies Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS anomalies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL NOT NULL,
                metric TEXT NOT NULL,
                severity TEXT NOT NULL CHECK(severity IN ('low', 'medium', 'high')),
                score REAL NOT NULL,
                value REAL NOT NULL,
                baseline REAL NOT NULL,
                z_score REAL NOT NULL,
                related_pid INTEGER,
                related_process TEXT,
                explanation TEXT NOT NULL
            );
            """)
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_anom_time ON anomalies (timestamp);"
            )
            cursor.execute(
                "CREATE INDEX IF NOT EXISTS idx_anom_sev ON anomalies (severity);"
            )

            # 4. Process Fingerprints Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS process_fingerprints (
                name TEXT PRIMARY KEY,
                sample_count INTEGER NOT NULL,
                mean_cpu REAL NOT NULL,
                std_cpu REAL NOT NULL,
                mean_mem REAL NOT NULL,
                std_mem REAL NOT NULL,
                mean_fds REAL NOT NULL,
                std_fds REAL NOT NULL,
                mean_threads REAL NOT NULL,
                std_threads REAL NOT NULL,
                last_updated REAL NOT NULL
            );
            """)

            conn.commit()

    def insert_system_metric(self, data: Dict[str, Any]) -> int:
        """Insert a single system metric snapshot.

        Args:
            data: System metric dictionary.

        Returns:
            The inserted row ID.
        """
        cpu_per_core_json = (
            json.dumps(data.get("cpu_per_core", []))
            if isinstance(data.get("cpu_per_core"), list)
            else "[]"
        )
        sql = """
        INSERT INTO system_metrics (
            timestamp, cpu_percent, cpu_per_core, load_1m, load_5m, load_15m,
            mem_used, mem_total, mem_percent, swap_used, swap_total, swap_percent,
            disk_read_bytes_sec, disk_write_bytes_sec, net_recv_bytes_sec, net_sent_bytes_sec,
            ctx_switches_sec, interrupts_sec, cpu_temp, proc_pulse_cpu, proc_pulse_mem_rss
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        params = (
            data["timestamp"],
            data["cpu_percent"],
            cpu_per_core_json,
            data["load_1m"],
            data["load_5m"],
            data["load_15m"],
            data["mem_used"],
            data["mem_total"],
            data["mem_percent"],
            data["swap_used"],
            data["swap_total"],
            data["swap_percent"],
            data["disk_read_bytes_sec"],
            data["disk_write_bytes_sec"],
            data["net_recv_bytes_sec"],
            data["net_sent_bytes_sec"],
            data["ctx_switches_sec"],
            data["interrupts_sec"],
            data.get("cpu_temp"),
            data.get("proc_pulse_cpu", 0.0),
            data.get("proc_pulse_mem_rss", 0),
        )
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()
            return cursor.lastrowid or 0

    def insert_process_metrics(self, procs: List[Dict[str, Any]]) -> int:
        """Batch insert snapshots of multiple processes.

        Args:
            procs: List of process telemetry dictionaries.

        Returns:
            Count of rows inserted.
        """
        if not procs:
            return 0

        sql = """
        INSERT INTO process_metrics (
            timestamp, pid, name, cmdline, cpu_percent, memory_rss,
            memory_percent, num_threads, num_fds, state, io_read_bytes, io_write_bytes
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        params = [
            (
                p["timestamp"],
                p["pid"],
                p["name"],
                p.get("cmdline", ""),
                p["cpu_percent"],
                p["memory_rss"],
                p["memory_percent"],
                p["num_threads"],
                p.get("num_fds", 0),
                p.get("state", "running"),
                p.get("io_read_bytes", 0),
                p.get("io_write_bytes", 0),
            )
            for p in procs
        ]
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany(sql, params)
            conn.commit()
            return cursor.rowcount

    def insert_anomaly(self, data: Dict[str, Any]) -> int:
        """Insert a detected anomaly event record.

        Args:
            data: Anomaly dictionary.

        Returns:
            Inserted anomaly row ID.
        """
        sql = """
        INSERT INTO anomalies (
            timestamp, metric, severity, score, value, baseline,
            z_score, related_pid, related_process, explanation
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
        """
        params = (
            data["timestamp"],
            data["metric"],
            data["severity"],
            data["score"],
            data["value"],
            data["baseline"],
            data["z_score"],
            data.get("related_pid"),
            data.get("related_process"),
            data["explanation"],
        )
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()
            return cursor.lastrowid or 0

    def upsert_fingerprint(self, fp: Dict[str, Any]) -> None:
        """Insert or update a process baseline behavioral fingerprint.

        Args:
            fp: Dictionary containing statistical fingerprint parameters.
        """
        sql = """
        INSERT INTO process_fingerprints (
            name, sample_count, mean_cpu, std_cpu, mean_mem, std_mem,
            mean_fds, std_fds, mean_threads, std_threads, last_updated
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ON CONFLICT(name) DO UPDATE SET
            sample_count = excluded.sample_count,
            mean_cpu = excluded.mean_cpu,
            std_cpu = excluded.std_cpu,
            mean_mem = excluded.mean_mem,
            std_mem = excluded.std_mem,
            mean_fds = excluded.mean_fds,
            std_fds = excluded.std_fds,
            mean_threads = excluded.mean_threads,
            std_threads = excluded.std_threads,
            last_updated = excluded.last_updated;
        """
        params = (
            fp["name"],
            fp["sample_count"],
            fp["mean_cpu"],
            fp["std_cpu"],
            fp["mean_mem"],
            fp["std_mem"],
            fp["mean_fds"],
            fp["std_fds"],
            fp["mean_threads"],
            fp["std_threads"],
            fp.get("last_updated", time.time()),
        )
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            conn.commit()

    def get_system_metrics(
        self, limit: int = 60, since: Optional[float] = None
    ) -> List[Dict[str, Any]]:
        """Retrieve recent time-series system metrics.

        Args:
            limit: Maximum number of rows to return.
            since: Optional cutoff timestamp filter.

        Returns:
            List of system metric records ordered ascending by timestamp.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            if since:
                sql = (
                    "SELECT * FROM system_metrics WHERE timestamp >= ? "
                    "ORDER BY timestamp ASC LIMIT ?;"
                )
                rows = cursor.execute(sql, (since, limit)).fetchall()
            else:
                sql = (
                    "SELECT * FROM system_metrics ORDER BY timestamp DESC LIMIT ?;"
                )
                rows = cursor.execute(sql, (limit,)).fetchall()
                rows = list(reversed(rows))

            results: List[Dict[str, Any]] = []
            for r in rows:
                item = dict(r)
                try:
                    item["cpu_per_core"] = json.loads(item["cpu_per_core"])
                except Exception:
                    item["cpu_per_core"] = []
                results.append(item)
            return results

    def get_recent_processes(self, limit: int = 15) -> List[Dict[str, Any]]:
        """Retrieve the most recent process metrics snapshot.

        Args:
            limit: Maximum processes to return.

        Returns:
            List of process dictionaries from latest timestamp.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            # Find the most recent timestamp in process_metrics
            t_row = cursor.execute(
                "SELECT MAX(timestamp) as max_t FROM process_metrics;"
            ).fetchone()
            if not t_row or t_row["max_t"] is None:
                return []
            latest_t = t_row["max_t"]

            rows = cursor.execute(
                "SELECT * FROM process_metrics WHERE timestamp = ? "
                "ORDER BY cpu_percent DESC, memory_percent DESC LIMIT ?;",
                (latest_t, limit),
            ).fetchall()
            return [dict(r) for r in rows]

    def get_anomalies(
        self,
        limit: int = 50,
        severity: Optional[str] = None,
        since: Optional[float] = None,
    ) -> List[Dict[str, Any]]:
        """Retrieve anomaly records.

        Args:
            limit: Maximum count.
            severity: Optional filter ('low', 'medium', 'high').
            since: Optional cutoff timestamp.

        Returns:
            List of anomaly dictionaries ordered by timestamp descending.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            query = "SELECT * FROM anomalies WHERE 1=1"
            params: List[Any] = []
            if severity:
                query += " AND severity = ?"
                params.append(severity)
            if since:
                query += " AND timestamp >= ?"
                params.append(since)
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)

            rows = cursor.execute(query, params).fetchall()
            return [dict(r) for r in rows]

    def get_fingerprints(self) -> Dict[str, Dict[str, Any]]:
        """Retrieve all process baseline fingerprints.

        Returns:
            Dictionary mapping process name to fingerprint dictionary.
        """
        with self._get_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT * FROM process_fingerprints;").fetchall()
            return {r["name"]: dict(r) for r in rows}

    def purge_old_records(self, retention_seconds: float) -> int:
        """Purge records older than retention period from time-series tables.

        Args:
            retention_seconds: How many seconds of history to keep.

        Returns:
            Total count of deleted rows across tables.
        """
        cutoff = time.time() - retention_seconds
        total_deleted = 0
        with self._lock, self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "DELETE FROM system_metrics WHERE timestamp < ?;", (cutoff,)
            )
            total_deleted += cursor.rowcount

            cursor.execute(
                "DELETE FROM process_metrics WHERE timestamp < ?;", (cutoff,)
            )
            total_deleted += cursor.rowcount

            cursor.execute(
                "DELETE FROM anomalies WHERE timestamp < ?;", (cutoff,)
            )
            total_deleted += cursor.rowcount

            conn.commit()
            if total_deleted > 0:
                logger.info(
                    "Purged %d old telemetry records before cutoff %s",
                    total_deleted,
                    cutoff,
                )
        return total_deleted
