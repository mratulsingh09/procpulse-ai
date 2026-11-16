"""FastAPI application factory and middleware configuration."""

from pathlib import Path
from typing import Optional, Any
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from procpulse.api.routes import router


def create_app(
    db=None,
    engine=None,
    system_collector=None,
    process_collector=None,
    lifespan=None,
) -> FastAPI:
    """Create and configure the FastAPI application.

    Args:
        db: Optional Database instance.
        engine: Optional AnomalyEngine instance.
        system_collector: Optional SystemCollector instance.
        process_collector: Optional ProcessCollector instance.
        lifespan: Optional async context manager for startup/shutdown.

    Returns:
        Configured FastAPI instance.
    """
    app_kwargs: dict = {
        "title": "ProcPulse AI — Real-Time Linux Telemetry & Anomaly Profiler",
        "description": "Live Linux system/process telemetry, ML anomaly detection, and real-time dashboard.",
        "version": "1.0.0",
    }
    if lifespan is not None:
        app_kwargs["lifespan"] = lifespan

    app = FastAPI(**app_kwargs)

    # Attach shared dependencies to app state
    app.state.db = db
    app.state.engine = engine
    app.state.system_collector = system_collector
    app.state.process_collector = process_collector

    # Mount API routes
    app.include_router(router)

    # Mount static dashboard files
    dashboard_dir = Path(__file__).parent / "dashboard"
    if dashboard_dir.is_dir():
        @app.get("/", response_class=FileResponse)
        async def serve_index():
            index_path = dashboard_dir / "index.html"
            if index_path.is_file():
                return FileResponse(index_path)
            return {"message": "ProcPulse AI Dashboard"}

        app.mount("/static", StaticFiles(directory=str(dashboard_dir)), name="static")

    return app
