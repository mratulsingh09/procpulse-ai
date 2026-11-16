"""Process-level telemetry collector.

Collects per-process telemetry: PID, name, CPU %, memory %, threads,
open file descriptors, state, and I/O. Gracefully handles vanished processes
and permission errors with minimal CPU overhead.
"""

import os
import time
import logging
from typing import Dict, List, Any, Optional
import psutil

from procpulse.collector.proc_parser import ProcParser
from procpulse.config import settings

logger = logging.getLogger(__name__)


class ProcessCollector:
    """Collects per-process statistics safely and efficiently."""

    def __init__(
        self,
        proc_path: Optional[str] = None,
        top_n: int = settings.top_processes_count,
    ) -> None:
        """Initialize process collector.

        Args:
            proc_path: Optional path to /proc; defaults to settings.proc_path.
            top_n: Number of top resource-consuming processes to return.
        """
        self.proc_parser = ProcParser(proc_path or settings.proc_path)
        self.top_n = top_n
        self._prev_proc_cpu: Dict[int, float] = {}

    def collect(self) -> List[Dict[str, Any]]:
        """Collect top active processes sorted by CPU and memory.

        Returns:
            List of process telemetry dictionaries.
        """
        processes: List[Dict[str, Any]] = []
        now = time.time()
        use_direct_proc = self.proc_parser.is_available

        # Iterate over processes safely
        for proc in psutil.process_iter(
            attrs=["pid", "name", "cpu_percent", "memory_info", "memory_percent", "num_threads", "status"]
        ):
            try:
                pinfo = proc.info
                pid = pinfo["pid"]
                if pid == 0:  # System idle process on Windows / special kernel
                    continue

                cpu_pct = pinfo.get("cpu_percent") or 0.0
                mem_info = pinfo.get("memory_info")
                mem_rss = mem_info.rss if mem_info else 0
                mem_pct = round(pinfo.get("memory_percent") or 0.0, 1)
                num_threads = pinfo.get("num_threads") or 1
                state = pinfo.get("status") or "running"
                name = pinfo.get("name") or "unknown"

                # Direct /proc augmentation if on Linux
                num_fds = 0
                cmdline = ""
                io_read_bytes = 0
                io_write_bytes = 0

                if use_direct_proc:
                    try:
                        num_fds = self.proc_parser.parse_pid_fds(pid)
                        cmdline = self.proc_parser.parse_pid_cmdline(pid)
                    except Exception:
                        pass
                else:
                    # On Windows/other, try num_handles or num_fds if available
                    try:
                        if hasattr(proc, "num_handles"):
                            num_fds = proc.num_handles()
                        elif hasattr(proc, "num_fds"):
                            num_fds = proc.num_fds()
                    except (psutil.AccessDenied, psutil.NoSuchProcess):
                        num_fds = 0

                    try:
                        cmdline = " ".join(proc.cmdline()[:5])
                    except (psutil.AccessDenied, psutil.NoSuchProcess, Exception):
                        cmdline = name

                # Process I/O counters if accessible
                try:
                    io_counters = proc.io_counters()
                    if io_counters:
                        io_read_bytes = io_counters.read_bytes
                        io_write_bytes = io_counters.write_bytes
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    pass

                processes.append({
                    "timestamp": now,
                    "pid": pid,
                    "name": name,
                    "cmdline": cmdline[:250] if cmdline else name,
                    "cpu_percent": round(cpu_pct, 1),
                    "memory_rss": mem_rss,
                    "memory_percent": mem_pct,
                    "num_threads": num_threads,
                    "num_fds": num_fds,
                    "state": state,
                    "io_read_bytes": io_read_bytes,
                    "io_write_bytes": io_write_bytes,
                })

            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception as e:
                logger.debug("Unexpected error reading process: %s", e)
                continue

        # Sort primarily by CPU%, secondarily by memory%
        processes.sort(key=lambda p: (p["cpu_percent"], p["memory_percent"]), reverse=True)
        return processes[: self.top_n]
