"""Configuration settings for ProcPulse AI."""

import os
import socket
from pathlib import Path
from pydantic import BaseModel, Field


def find_available_port(preferred_port: int, host: str = "0.0.0.0", max_tries: int = 20) -> int:
    """Return the preferred port when free, otherwise the next available one."""
    candidates = [preferred_port] + list(range(preferred_port + 1, preferred_port + max_tries + 1))

    for port in candidates:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                sock.bind((host, port))
                return port
            except OSError:
                continue

    raise OSError(f"No free port available starting from {preferred_port} on host {host}.")


class Settings(BaseModel):
    """Application configuration settings."""

    # Server Settings
    host: str = Field(
        default_factory=lambda: os.getenv("PROCPULSE_HOST", "0.0.0.0"),
        description="Host address for FastAPI server",
    )
    port: int = Field(
        default_factory=lambda: int(os.getenv("PROCPULSE_PORT", os.getenv("PORT", "8000"))),
        description="Port for FastAPI server",
    )
    debug: bool = Field(default=False, description="Debug mode flag")

    # Collector Settings
    collection_interval_sec: float = Field(
        default=1.0, description="Telemetry polling interval in seconds"
    )
    proc_path: str = Field(
        default=os.getenv("PROCPULSE_PROC_PATH", "/proc"),
        description="Path to Linux /proc virtual filesystem",
    )
    top_processes_count: int = Field(
        default=15, description="Number of top processes to track and broadcast"
    )

    # Storage Settings
    db_path: str = Field(
        default=str(Path(__file__).resolve().parent.parent / "procpulse.db"),
        description="Path to SQLite database file",
    )
    retention_hours: float = Field(
        default=2.0, description="Hours of historical metrics to retain in SQLite"
    )
    purge_interval_sec: int = Field(
        default=300, description="Interval in seconds for purging old data"
    )

    # Anomaly Engine Settings
    warmup_samples: int = Field(
        default=10, description="Number of ticks before raising anomaly alerts"
    )
    ewma_alpha: float = Field(
        default=0.15, description="Smoothing factor alpha for EWMA baseline"
    )
    zscore_low_threshold: float = Field(
        default=2.5, description="Z-score threshold for LOW severity"
    )
    zscore_medium_threshold: float = Field(
        default=3.5, description="Z-score threshold for MEDIUM severity"
    )
    zscore_high_threshold: float = Field(
        default=4.5, description="Z-score threshold for HIGH severity"
    )
    isolation_forest_retrain_interval_sec: int = Field(
        default=60, description="Interval in seconds to retrain IsolationForest"
    )
    isolation_forest_history_size: int = Field(
        default=300, description="Number of past samples used to train IsolationForest"
    )
    isolation_forest_contamination: float = Field(
        default=0.03, description="Contamination factor for IsolationForest"
    )


# Global settings singleton
settings = Settings()
