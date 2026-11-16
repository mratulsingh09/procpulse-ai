"""Main application entrypoint and background telemetry orchestration loop."""

import asyncio
import logging
import sys
import time
from contextlib import asynccontextmanager
from fastapi import FastAPI
import uvicorn

from procpulse.config import find_available_port, settings
from procpulse.collector.system import SystemCollector
from procpulse.collector.process import ProcessCollector
from procpulse.storage.database import Database
from procpulse.engine.detector import AnomalyEngine
from procpulse.api.websocket import ws_manager
from procpulse.api.routes import router
from procpulse.app import create_app

# Configure structured logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger("procpulse")

# Global shared components
db: Database = Database(settings.db_path)
system_collector: SystemCollector = SystemCollector(settings.proc_path)
process_collector: ProcessCollector = ProcessCollector(
    settings.proc_path, top_n=settings.top_processes_count
)
engine: AnomalyEngine = AnomalyEngine(
    warmup_samples=settings.warmup_samples,
    ewma_alpha=settings.ewma_alpha,
    low_threshold=settings.zscore_low_threshold,
    med_threshold=settings.zscore_medium_threshold,
    high_threshold=settings.zscore_high_threshold,
)

_collection_task: asyncio.Task = None  # type: ignore[assignment]
_running = True


async def telemetry_background_loop() -> None:
    """Asynchronous background loop collecting, storing, profiling, and broadcasting telemetry."""
    logger.info(
        "ProcPulse telemetry loop started (Interval: %.1fs, Warmup: %d ticks, Retention: %.1fh)",
        settings.collection_interval_sec,
        settings.warmup_samples,
        settings.retention_hours,
    )
    last_purge_time = time.time()
    retention_seconds = settings.retention_hours * 3600.0

    while _running:
        loop_start = time.time()
        try:
            # 1. Collect System & Process Telemetry
            sys_data = system_collector.collect()
            procs = process_collector.collect()

            # 2. Run Anomaly Engine
            new_anomalies = engine.process_tick(sys_data, procs)

            # 3. Store into SQLite
            db.insert_system_metric(sys_data)
            db.insert_process_metrics(procs)
            for anom in new_anomalies:
                db.insert_anomaly(anom)
                logger.warning("ANOMALY [%s]: %s", anom["severity"].upper(), anom["explanation"])

            # 4. Build and broadcast WebSocket payload
            health_score, health_status = engine.get_health_score()
            payload = {
                "system": sys_data,
                "top_processes": procs,
                "latest_anomalies": new_anomalies,
                "health_score": health_score,
                "health_status": health_status,
                "overhead": {
                    "cpu_percent": sys_data.get("proc_pulse_cpu", 0.0),
                    "memory_rss_bytes": sys_data.get("proc_pulse_mem_rss", 0),
                    "memory_rss_mb": round(sys_data.get("proc_pulse_mem_rss", 0) / (1024 * 1024), 1),
                },
                "suspicious": engine.get_suspicious_processes(),
            }
            await ws_manager.broadcast(payload)

            # 5. Periodic retention purge
            now = time.time()
            if now - last_purge_time >= settings.purge_interval_sec:
                db.purge_old_records(retention_seconds)
                last_purge_time = now

        except Exception as e:
            logger.error("Exception in telemetry loop: %s", e, exc_info=True)

        elapsed = time.time() - loop_start
        await asyncio.sleep(max(0.05, settings.collection_interval_sec - elapsed))


@asynccontextmanager
async def lifespan(fastapi_app: FastAPI):
    """FastAPI lifespan context manager to start and stop background tasks."""
    global _collection_task, _running
    _running = True
    _collection_task = asyncio.create_task(telemetry_background_loop())
    logger.info("ProcPulse AI started. Dashboard: http://localhost:%d", settings.port)
    try:
        yield
    finally:
        _running = False
        if _collection_task:
            _collection_task.cancel()
            try:
                await asyncio.wait_for(_collection_task, timeout=2.0)
            except (asyncio.CancelledError, asyncio.TimeoutError):
                pass
        logger.info("ProcPulse AI shutdown complete.")


# Build app with lifespan and all dependencies
app = create_app(
    db=db,
    engine=engine,
    system_collector=system_collector,
    process_collector=process_collector,
    lifespan=lifespan,
)


def run() -> None:
    """Launch Uvicorn HTTP/WebSocket server."""
    settings.port = find_available_port(settings.port, settings.host)
    print("=" * 65)
    print("  ProcPulse AI — Real-Time Linux Telemetry & Anomaly Profiler")
    print(f"  Live Web Dashboard: http://localhost:{settings.port}")
    print("=" * 65)
    uvicorn.run(
        app,
        host=settings.host,
        port=settings.port,
        log_level="info",
        access_log=False,
    )


if __name__ == "__main__":
    run()
