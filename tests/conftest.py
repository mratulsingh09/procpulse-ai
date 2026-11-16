"""Pytest configuration and shared fixtures."""

import os
import shutil
import tempfile
from pathlib import Path
import pytest


@pytest.fixture
def mock_proc_dir(tmp_path: Path) -> Path:
    """Create a realistic mock Linux /proc filesystem tree for tests."""
    proc = tmp_path / "proc"
    proc.mkdir()

    # 1. /proc/stat
    stat_content = (
        "cpu  101234 500 20500 802345 1200 450 150 0 0 0\n"
        "cpu0 50000 250 10000 400000 600 200 75 0 0 0\n"
        "cpu1 51234 250 10500 402345 600 250 75 0 0 0\n"
        "ctxt 12345678\n"
        "intr 9876543 1 2 3\n"
        "processes 54321\n"
        "procs_running 2\n"
        "procs_blocked 0\n"
    )
    (proc / "stat").write_text(stat_content, encoding="utf-8")

    # 2. /proc/loadavg
    (proc / "loadavg").write_text("0.45 0.32 0.18 1/350 4912\n", encoding="utf-8")

    # 3. /proc/meminfo
    meminfo_content = (
        "MemTotal:       16384000 kB\n"
        "MemFree:         4096000 kB\n"
        "MemAvailable:    8192000 kB\n"
        "Buffers:          512000 kB\n"
        "Cached:          3584000 kB\n"
        "SwapTotal:       4194304 kB\n"
        "SwapFree:        3145728 kB\n"
    )
    (proc / "meminfo").write_text(meminfo_content, encoding="utf-8")

    # 4. /proc/diskstats
    diskstats_content = (
        "   8       0 sda 1000 200 20480 500 500 100 10240 250 0 750 750 0 0 0 0\n"
        "   7       0 loop0 10 0 20 5 0 0 0 0 0 5 5 0 0 0 0\n"
    )
    (proc / "diskstats").write_text(diskstats_content, encoding="utf-8")

    # 5. /proc/net/dev
    netdev_content = (
        "Inter-|   Receive                                                |  Transmit\n"
        " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n"
        "    lo: 1234567      50    0    0    0     0          0         0  1234567      50    0    0    0     0       0          0\n"
        "  eth0: 50000000   10000    0    0    0     0          0         0 25000000    5000    0    0    0     0       0          0\n"
    )
    (proc / "net").mkdir(parents=True)
    (proc / "net" / "dev").write_text(netdev_content, encoding="utf-8")

    # 6. /proc/1234 (Sample process)
    pid_dir = proc / "1234"
    pid_dir.mkdir()
    # comm with spaces to test parsing
    pid_stat = "1234 (python worker) R 1 1234 1234 0 -1 4194304 100 200 0 0 1500 800 0 0 20 0 4 0 1000 52428800 2000\n"
    (pid_dir / "stat").write_text(pid_stat, encoding="utf-8")

    pid_status = (
        "Name:\tpython worker\n"
        "State:\tR (running)\n"
        "Tgid:\t1234\n"
        "Pid:\t1234\n"
        "PPid:\t1\n"
        "FDSize:\t64\n"
        "VmSize:\t  102400 kB\n"
        "VmRSS:\t   40960 kB\n"
        "Threads:\t4\n"
    )
    (pid_dir / "status").write_text(pid_status, encoding="utf-8")

    # Mock FDs
    fd_dir = pid_dir / "fd"
    fd_dir.mkdir()
    (fd_dir / "0").touch()
    (fd_dir / "1").touch()
    (fd_dir / "2").touch()
    (fd_dir / "3").touch()

    # Mock cmdline
    (pid_dir / "cmdline").write_bytes(b"python\x00worker.py\x00--threads\x004\x00")

    return proc
