"""System-level telemetry collector.

Collects aggregate and per-core CPU, load average, memory, swap, disk I/O,
network I/O, context switches, interrupts, CPU temperature, and self-overhead.
Integrates direct /proc parsing with psutil cross-platform fallback.
"""

import os
import time
import json
import logging
from typing import Dict, Any, Optional
import psutil

from procpulse.collector.proc_parser import ProcParser
from procpulse.config import settings

logger = logging.getLogger(__name__)


class SystemCollector:
    """Collects real-time system-wide hardware and OS metrics."""

    def __init__(self, proc_path: Optional[str] = None) -> None:
        """Initialize the system collector.

        Args:
            proc_path: Optional path to /proc; defaults to settings.proc_path.
        """
        self.proc_parser = ProcParser(proc_path or settings.proc_path)
        self._prev_time: float = time.time()
        self._prev_disk_io: Optional[Any] = None
        self._prev_net_io: Optional[Any] = None
        self._prev_stat: Optional[Dict[str, Any]] = None
        self._self_process: psutil.Process = psutil.Process(os.getpid())
        self._last_overhead_cpu: float = 0.0

        # Seed initial CPU reading so next sample has accurate delta
        psutil.cpu_percent(interval=None)
        psutil.cpu_percent(percpu=True, interval=None)
        # Seed self-process CPU measurement to get accurate next reading
        self._self_process.cpu_percent(interval=None)

    def collect(self) -> Dict[str, Any]:
        """Collect a full snapshot of system metrics.

        Returns:
            Dictionary containing system performance telemetry.
        """
        now = time.time()
        delta_t = max(0.001, now - self._prev_time)
        self._prev_time = now

        # 1. CPU Metrics
        use_direct_proc = self.proc_parser.is_available
        if use_direct_proc:
            raw_stat = self.proc_parser.parse_stat()
            cpu_total, cpu_per_core = self.proc_parser.calculate_cpu_percent(raw_stat)
            # If direct proc returned 0 across both ticks on first read, fallback to psutil
            if cpu_total == 0.0 and not self._prev_stat:
                cpu_total = psutil.cpu_percent(interval=None)
                cpu_per_core = psutil.cpu_percent(percpu=True, interval=None)
        else:
            raw_stat = {}
            cpu_total = psutil.cpu_percent(interval=None)
            cpu_per_core = psutil.cpu_percent(percpu=True, interval=None)

        # 2. Load Average
        if use_direct_proc:
            load_1m, load_5m, load_15m = self.proc_parser.parse_loadavg()
        else:
            try:
                load_1m, load_5m, load_15m = psutil.getloadavg()
            except (AttributeError, OSError, RuntimeError):
                # Windows sometimes raises RuntimeError for PDH counters
                cpu_norm = max(0.0, min(1.0, cpu_total / 100.0))
                n_cpus = os.cpu_count() or 1
                load_1m = round(cpu_norm * n_cpus, 2)
                load_5m = load_1m
                load_15m = load_1m

        # 3. Memory & Swap
        if use_direct_proc:
            meminfo = self.proc_parser.parse_meminfo()
            mem_total = meminfo.get("MemTotal", 0)
            mem_avail = meminfo.get("MemAvailable", meminfo.get("MemFree", 0))
            mem_used = max(0, mem_total - mem_avail)
            mem_percent = round((mem_used / mem_total * 100.0), 1) if mem_total > 0 else 0.0

            swap_total = meminfo.get("SwapTotal", 0)
            swap_free = meminfo.get("SwapFree", 0)
            swap_used = max(0, swap_total - swap_free)
            swap_percent = round((swap_used / swap_total * 100.0), 1) if swap_total > 0 else 0.0
        else:
            vm = psutil.virtual_memory()
            mem_total = vm.total
            mem_used = vm.used
            mem_percent = round(vm.percent, 1)

            try:
                sw = psutil.swap_memory()
                swap_total = sw.total
                swap_used = sw.used
                swap_percent = round(sw.percent, 1)
            except (RuntimeError, OSError):
                # Swap unavailable on some Windows configurations (PDH counters disabled)
                swap_total = 0
                swap_used = 0
                swap_percent = 0.0

        # 4. Disk I/O Rate
        disk_read_bytes_sec = 0.0
        disk_write_bytes_sec = 0.0
        try:
            current_disk_io = psutil.disk_io_counters()
            if current_disk_io and self._prev_disk_io:
                disk_read_bytes_sec = max(
                    0.0, (current_disk_io.read_bytes - self._prev_disk_io.read_bytes) / delta_t
                )
                disk_write_bytes_sec = max(
                    0.0, (current_disk_io.write_bytes - self._prev_disk_io.write_bytes) / delta_t
                )
            self._prev_disk_io = current_disk_io
        except Exception as e:
            logger.debug("Disk I/O collection error: %s", e)

        # 5. Network I/O Rate
        net_recv_bytes_sec = 0.0
        net_sent_bytes_sec = 0.0
        try:
            current_net_io = psutil.net_io_counters()
            if current_net_io and self._prev_net_io:
                net_recv_bytes_sec = max(
                    0.0, (current_net_io.bytes_recv - self._prev_net_io.bytes_recv) / delta_t
                )
                net_sent_bytes_sec = max(
                    0.0, (current_net_io.bytes_sent - self._prev_net_io.bytes_sent) / delta_t
                )
            self._prev_net_io = current_net_io
        except Exception as e:
            logger.debug("Network I/O collection error: %s", e)

        # 6. Context Switches & Interrupts
        ctx_switches_sec = 0.0
        interrupts_sec = 0.0
        try:
            cpu_stats = psutil.cpu_stats()
            if self._prev_stat and hasattr(self._prev_stat, "ctx_switches"):
                ctx_switches_sec = max(
                    0.0, (cpu_stats.ctx_switches - self._prev_stat.ctx_switches) / delta_t
                )
                interrupts_sec = max(
                    0.0, (cpu_stats.interrupts - self._prev_stat.interrupts) / delta_t
                )
            self._prev_stat = cpu_stats
        except Exception as e:
            logger.debug("CPU stats collection error: %s", e)

        # 7. CPU Temperature (if hardware sensors available)
        cpu_temp: Optional[float] = None
        try:
            if hasattr(psutil, "sensors_temperatures"):
                temps = psutil.sensors_temperatures()
                if temps:
                    # Pick first available core/package temp
                    for name, entries in temps.items():
                        if entries:
                            cpu_temp = entries[0].current
                            break
        except Exception:
            cpu_temp = None

        # 8. Self-Monitoring Overhead
        # NOTE: cpu_percent(interval=None) returns CPU since previous call.
        # It's called every 1-second tick from the collector loop, giving accurate rolling overhead.
        proc_pulse_cpu = 0.0
        proc_pulse_mem_rss = 0
        try:
            raw_cpu = self._self_process.cpu_percent(interval=None)
            # Smooth with EWMA to reduce momentary spikes (alpha = 0.3)
            self._last_overhead_cpu = round(0.7 * self._last_overhead_cpu + 0.3 * raw_cpu, 2)
            proc_pulse_cpu = self._last_overhead_cpu
            proc_pulse_mem_rss = self._self_process.memory_info().rss
        except Exception:
            pass

        return {
            "timestamp": now,
            "cpu_percent": round(cpu_total, 1),
            "cpu_per_core": cpu_per_core,
            "load_1m": round(load_1m, 2),
            "load_5m": round(load_5m, 2),
            "load_15m": round(load_15m, 2),
            "mem_used": mem_used,
            "mem_total": mem_total,
            "mem_percent": mem_percent,
            "swap_used": swap_used,
            "swap_total": swap_total,
            "swap_percent": swap_percent,
            "disk_read_bytes_sec": round(disk_read_bytes_sec, 1),
            "disk_write_bytes_sec": round(disk_write_bytes_sec, 1),
            "net_recv_bytes_sec": round(net_recv_bytes_sec, 1),
            "net_sent_bytes_sec": round(net_sent_bytes_sec, 1),
            "ctx_switches_sec": round(ctx_switches_sec, 1),
            "interrupts_sec": round(interrupts_sec, 1),
            "cpu_temp": cpu_temp,
            "proc_pulse_cpu": proc_pulse_cpu,
            "proc_pulse_mem_rss": proc_pulse_mem_rss,
        }
