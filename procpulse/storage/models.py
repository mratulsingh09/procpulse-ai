"""Data models and schemas for ProcPulse storage and telemetry."""

from typing import List, Optional
from pydantic import BaseModel, Field


class SystemMetric(BaseModel):
    """Snapshot of system-level performance telemetry."""

    timestamp: float
    cpu_percent: float
    cpu_per_core: List[float] = Field(default_factory=list)
    load_1m: float
    load_5m: float
    load_15m: float
    mem_used: int
    mem_total: int
    mem_percent: float
    swap_used: int
    swap_total: int
    swap_percent: float
    disk_read_bytes_sec: float
    disk_write_bytes_sec: float
    net_recv_bytes_sec: float
    net_sent_bytes_sec: float
    ctx_switches_sec: float
    interrupts_sec: float
    cpu_temp: Optional[float] = None
    proc_pulse_cpu: float = 0.0
    proc_pulse_mem_rss: int = 0


class ProcessMetric(BaseModel):
    """Snapshot of a single process's telemetry."""

    timestamp: float
    pid: int
    name: str
    cmdline: str = ""
    cpu_percent: float
    memory_rss: int
    memory_percent: float
    num_threads: int
    num_fds: int = 0
    state: str = "running"
    io_read_bytes: int = 0
    io_write_bytes: int = 0


class AnomalyRecord(BaseModel):
    """Detected anomaly event with metrics and plain-English explanation."""

    timestamp: float
    metric: str
    severity: str  # 'low', 'medium', 'high'
    score: float
    value: float
    baseline: float
    z_score: float
    related_pid: Optional[int] = None
    related_process: Optional[str] = None
    explanation: str


class ProcessFingerprint(BaseModel):
    """Statistical profile of baseline behavior for a known process name."""

    name: str
    sample_count: int
    mean_cpu: float
    std_cpu: float
    mean_mem: float
    std_mem: float
    mean_fds: float
    std_fds: float
    mean_threads: float
    std_threads: float
    last_updated: float
