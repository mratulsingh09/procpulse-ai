"""Direct Linux /proc virtual filesystem parser.

Provides low-level parsing of Linux /proc statistics (/proc/stat, /proc/loadavg,
/proc/meminfo, /proc/diskstats, /proc/net/dev, and /proc/[pid]/*) with zero
external dependencies. Gracefully falls back when /proc is absent or unreadable.
"""

import os
import re
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger(__name__)


class ProcParser:
    """Parser for Linux /proc virtual filesystem."""

    def __init__(self, proc_path: str = "/proc") -> None:
        """Initialize parser with path to /proc.

        Args:
            proc_path: Filesystem path to /proc (defaults to '/proc').
        """
        self.proc_path = Path(proc_path)
        self._prev_cpu_times: Dict[str, Tuple[int, int]] = {}
        self._prev_pid_cpu_times: Dict[int, Tuple[float, float]] = {}  # pid -> (timestamp, total_jiffies)

    @property
    def is_available(self) -> bool:
        """Check if target /proc path exists and has /proc/stat."""
        try:
            return (self.proc_path / "stat").is_file()
        except Exception:
            return False

    def parse_stat(self) -> Dict[str, Any]:
        """Parse /proc/stat for CPU ticks, context switches, and interrupts.

        Returns:
            Dictionary containing cpu ticks, per-cpu ticks, ctxt, and intr counts.
        """
        stat_file = self.proc_path / "stat"
        if not stat_file.is_file():
            return {}

        data: Dict[str, Any] = {
            "cpus": {},
            "ctxt": 0,
            "intr": 0,
            "processes": 0,
            "procs_running": 0,
            "procs_blocked": 0,
        }

        try:
            with open(stat_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    parts = line.split()
                    if not parts:
                        continue
                    key = parts[0]
                    if key == "cpu" or key.startswith("cpu"):
                        # Fields: user nice system idle iowait irq softirq steal guest guest_nice
                        fields = [int(p) for p in parts[1:]]
                        data["cpus"][key] = fields
                    elif key == "ctxt":
                        data["ctxt"] = int(parts[1])
                    elif key == "intr":
                        data["intr"] = int(parts[1])
                    elif key == "processes":
                        data["processes"] = int(parts[1])
                    elif key == "procs_running":
                        data["procs_running"] = int(parts[1])
                    elif key == "procs_blocked":
                        data["procs_blocked"] = int(parts[1])
        except Exception as e:
            logger.debug("Failed to read %s: %s", stat_file, e)

        return data

    def calculate_cpu_percent(self, stat_data: Dict[str, Any]) -> Tuple[float, List[float]]:
        """Calculate aggregate and per-core CPU usage percentages from /proc/stat.

        Args:
            stat_data: Parsed dictionary from parse_stat().

        Returns:
            Tuple of (overall_cpu_percent, list_of_per_core_percents).
        """
        cpus = stat_data.get("cpus", {})
        if not cpus:
            return 0.0, []

        overall_pct = 0.0
        per_core_pcts: List[float] = []

        # Calculate for overall cpu
        if "cpu" in cpus:
            fields = cpus["cpu"]
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
            total = sum(fields)
            if "cpu" in self._prev_cpu_times:
                prev_idle, prev_total = self._prev_cpu_times["cpu"]
                delta_total = max(1, total - prev_total)
                delta_idle = max(0, idle - prev_idle)
                overall_pct = max(0.0, min(100.0, (1.0 - (delta_idle / delta_total)) * 100.0))
            self._prev_cpu_times["cpu"] = (idle, total)

        # Calculate for per-core cpu (cpu0, cpu1, ...)
        core_keys = sorted([k for k in cpus.keys() if k.startswith("cpu") and k != "cpu"],
                           key=lambda x: int(x[3:]) if x[3:].isdigit() else 0)
        for core_key in core_keys:
            fields = cpus[core_key]
            idle = fields[3] + (fields[4] if len(fields) > 4 else 0)
            total = sum(fields)
            core_pct = 0.0
            if core_key in self._prev_cpu_times:
                prev_idle, prev_total = self._prev_cpu_times[core_key]
                delta_total = max(1, total - prev_total)
                delta_idle = max(0, idle - prev_idle)
                core_pct = max(0.0, min(100.0, (1.0 - (delta_idle / delta_total)) * 100.0))
            self._prev_cpu_times[core_key] = (idle, total)
            per_core_pcts.append(round(core_pct, 1))

        return round(overall_pct, 1), per_core_pcts

    def parse_loadavg(self) -> Tuple[float, float, float]:
        """Parse /proc/loadavg for 1, 5, and 15-minute load averages.

        Returns:
            Tuple of (load_1m, load_5m, load_15m).
        """
        load_file = self.proc_path / "loadavg"
        if not load_file.is_file():
            return 0.0, 0.0, 0.0

        try:
            with open(load_file, "r", encoding="utf-8") as f:
                content = f.read().strip().split()
                if len(content) >= 3:
                    return float(content[0]), float(content[1]), float(content[2])
        except Exception as e:
            logger.debug("Failed to read %s: %s", load_file, e)

        return 0.0, 0.0, 0.0

    def parse_meminfo(self) -> Dict[str, int]:
        """Parse /proc/meminfo into a byte-denominated dictionary.

        Returns:
            Dictionary with MemTotal, MemFree, MemAvailable, Buffers,
            Cached, SwapTotal, SwapFree, etc. in bytes.
        """
        mem_file = self.proc_path / "meminfo"
        result: Dict[str, int] = {}
        if not mem_file.is_file():
            return result

        try:
            with open(mem_file, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split(":")
                    if len(parts) == 2:
                        key = parts[0].strip()
                        val_str = parts[1].strip().split()[0]
                        # Values in /proc/meminfo are in kB
                        result[key] = int(val_str) * 1024
        except Exception as e:
            logger.debug("Failed to read %s: %s", mem_file, e)

        return result

    def parse_diskstats(self) -> Tuple[int, int]:
        """Parse /proc/diskstats for cumulative disk read and write bytes.

        Returns:
            Tuple of (cumulative_read_bytes, cumulative_write_bytes).
        """
        disk_file = self.proc_path / "diskstats"
        total_read_sectors = 0
        total_write_sectors = 0

        if not disk_file.is_file():
            return 0, 0

        try:
            with open(disk_file, "r", encoding="utf-8") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 14:
                        dev_name = parts[2]
                        # Filter out loop, ram, and partition duplicates (keep sdX, nvmeXnX, vdX)
                        if dev_name.startswith(("loop", "ram", "dm-")):
                            continue
                        # Field 5: sectors read, Field 9: sectors written
                        try:
                            total_read_sectors += int(parts[5])
                            total_write_sectors += int(parts[9])
                        except (ValueError, IndexError):
                            pass
        except Exception as e:
            logger.debug("Failed to read %s: %s", disk_file, e)

        # 1 sector = 512 bytes on Linux
        return total_read_sectors * 512, total_write_sectors * 512

    def parse_net_dev(self) -> Tuple[int, int, int, int]:
        """Parse /proc/net/dev for network traffic stats.

        Returns:
            Tuple of (rx_bytes, tx_bytes, rx_packets, tx_packets).
        """
        net_file = self.proc_path / "net" / "dev"
        rx_bytes = tx_bytes = rx_packets = tx_packets = 0

        if not net_file.is_file():
            return 0, 0, 0, 0

        try:
            with open(net_file, "r", encoding="utf-8") as f:
                lines = f.readlines()
                # Skip header lines (first 2 lines)
                for line in lines[2:]:
                    if ":" not in line:
                        continue
                    iface, stats = line.split(":", 1)
                    iface = iface.strip()
                    if iface == "lo":  # Ignore loopback
                        continue
                    parts = stats.split()
                    if len(parts) >= 16:
                        rx_bytes += int(parts[0])
                        rx_packets += int(parts[1])
                        tx_bytes += int(parts[8])
                        tx_packets += int(parts[9])
        except Exception as e:
            logger.debug("Failed to read %s: %s", net_file, e)

        return rx_bytes, tx_bytes, rx_packets, tx_packets

    def parse_pid_stat(self, pid: int) -> Optional[Dict[str, Any]]:
        """Parse /proc/[pid]/stat for process details.

        Args:
            pid: Process ID.

        Returns:
            Dictionary with pid, name, state, ppid, utime, stime, num_threads or None.
        """
        stat_file = self.proc_path / str(pid) / "stat"
        if not stat_file.is_file():
            return None

        try:
            with open(stat_file, "r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()

            # Process comm name is enclosed in parentheses, which can contain spaces
            match = re.search(r"^(\d+)\s+\((.*)\)\s+([RSDZTW])\s+(.*)$", content)
            if not match:
                return None

            pid_str, comm, state, rest = match.groups()
            rest_parts = rest.split()
            # Fields in rest:
            # 0: ppid, 1: pgrp, 2: session, 3: tty_nr, 4: tpgid, 5: flags,
            # 6: minflt, 7: cminflt, 8: majflt, 9: cmajflt,
            # 10: utime, 11: stime, 12: cutime, 13: cstime, 14: priority, 15: nice, 16: num_threads
            ppid = int(rest_parts[0]) if len(rest_parts) > 0 else 0
            utime = int(rest_parts[10]) if len(rest_parts) > 10 else 0
            stime = int(rest_parts[11]) if len(rest_parts) > 11 else 0
            threads = int(rest_parts[16]) if len(rest_parts) > 16 else 1

            return {
                "pid": int(pid_str),
                "name": comm,
                "state": state,
                "ppid": ppid,
                "utime": utime,
                "stime": stime,
                "num_threads": threads,
            }
        except Exception as e:
            logger.debug("Failed to parse /proc/%s/stat: %s", pid, e)
            return None

    def parse_pid_status(self, pid: int) -> Dict[str, Any]:
        """Parse /proc/[pid]/status for VmRSS, VmSize, Threads, and FDSize.

        Args:
            pid: Process ID.

        Returns:
            Dictionary with rss_bytes, vms_bytes, threads, and fd_size.
        """
        status_file = self.proc_path / str(pid) / "status"
        res = {"rss_bytes": 0, "vms_bytes": 0, "threads": 1, "fd_size": 0}
        if not status_file.is_file():
            return res

        try:
            with open(status_file, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("VmRSS:"):
                        res["rss_bytes"] = int(line.split()[1]) * 1024
                    elif line.startswith("VmSize:"):
                        res["vms_bytes"] = int(line.split()[1]) * 1024
                    elif line.startswith("Threads:"):
                        res["threads"] = int(line.split()[1])
                    elif line.startswith("FDSize:"):
                        res["fd_size"] = int(line.split()[1])
        except Exception as e:
            logger.debug("Failed to parse /proc/%s/status: %s", pid, e)

        return res

    def parse_pid_fds(self, pid: int) -> int:
        """Count open file descriptors by reading /proc/[pid]/fd.

        Args:
            pid: Process ID.

        Returns:
            Number of open file descriptors or 0 if inaccessible.
        """
        fd_dir = self.proc_path / str(pid) / "fd"
        try:
            if fd_dir.is_dir():
                return len(list(fd_dir.iterdir()))
        except Exception:
            pass
        return 0

    def parse_pid_cmdline(self, pid: int) -> str:
        """Parse /proc/[pid]/cmdline.

        Args:
            pid: Process ID.

        Returns:
            Clean command line string or empty string.
        """
        cmd_file = self.proc_path / str(pid) / "cmdline"
        try:
            if cmd_file.is_file():
                with open(cmd_file, "rb") as f:
                    content = f.read().decode("utf-8", errors="replace")
                    return content.replace("\x00", " ").strip()
        except Exception:
            pass
        return ""
