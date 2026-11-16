"""Unit tests for proc_parser, SystemCollector, and ProcessCollector."""

from pathlib import Path
from procpulse.collector.proc_parser import ProcParser
from procpulse.collector.system import SystemCollector
from procpulse.collector.process import ProcessCollector


def test_proc_parser_availability(mock_proc_dir: Path):
    """Test ProcParser correctly detects /proc existence."""
    parser = ProcParser(str(mock_proc_dir))
    assert parser.is_available is True

    fake_parser = ProcParser("/non_existent_proc_path_12345")
    assert fake_parser.is_available is False


def test_proc_parser_stat_and_cpu(mock_proc_dir: Path):
    """Test parsing /proc/stat for cpus, ctxt, and intr."""
    parser = ProcParser(str(mock_proc_dir))
    stat = parser.parse_stat()

    assert "cpu" in stat["cpus"]
    assert "cpu0" in stat["cpus"]
    assert "cpu1" in stat["cpus"]
    assert stat["ctxt"] == 12345678
    assert stat["intr"] == 9876543
    assert stat["processes"] == 54321

    # First CPU calculation records baseline
    cpu_pct, per_core = parser.calculate_cpu_percent(stat)
    assert isinstance(cpu_pct, float)
    assert len(per_core) == 2


def test_proc_parser_loadavg(mock_proc_dir: Path):
    """Test parsing /proc/loadavg."""
    parser = ProcParser(str(mock_proc_dir))
    l1, l5, l15 = parser.parse_loadavg()
    assert l1 == 0.45
    assert l5 == 0.32
    assert l15 == 0.18


def test_proc_parser_meminfo(mock_proc_dir: Path):
    """Test parsing /proc/meminfo."""
    parser = ProcParser(str(mock_proc_dir))
    mem = parser.parse_meminfo()
    assert mem["MemTotal"] == 16384000 * 1024
    assert mem["MemFree"] == 4096000 * 1024
    assert mem["SwapTotal"] == 4194304 * 1024


def test_proc_parser_diskstats(mock_proc_dir: Path):
    """Test parsing /proc/diskstats."""
    parser = ProcParser(str(mock_proc_dir))
    read_bytes, write_bytes = parser.parse_diskstats()
    # sda has 20480 sectors read * 512, 10240 sectors written * 512
    assert read_bytes == 20480 * 512
    assert write_bytes == 10240 * 512


def test_proc_parser_net_dev(mock_proc_dir: Path):
    """Test parsing /proc/net/dev excluding loopback."""
    parser = ProcParser(str(mock_proc_dir))
    rx_bytes, tx_bytes, rx_packets, tx_packets = parser.parse_net_dev()
    assert rx_bytes == 50000000
    assert tx_bytes == 25000000
    assert rx_packets == 10000
    assert tx_packets == 5000


def test_proc_parser_pid(mock_proc_dir: Path):
    """Test parsing /proc/[pid]/stat, status, fd, cmdline."""
    parser = ProcParser(str(mock_proc_dir))
    stat = parser.parse_pid_stat(1234)
    assert stat is not None
    assert stat["pid"] == 1234
    assert stat["name"] == "python worker"
    assert stat["state"] == "R"
    assert stat["num_threads"] == 4

    status = parser.parse_pid_status(1234)
    assert status["rss_bytes"] == 40960 * 1024
    assert status["threads"] == 4

    fds = parser.parse_pid_fds(1234)
    assert fds == 4

    cmdline = parser.parse_pid_cmdline(1234)
    assert "python worker.py --threads 4" in cmdline


def test_system_collector_collection(mock_proc_dir: Path):
    """Test SystemCollector collects a valid telemetry snapshot."""
    collector = SystemCollector(proc_path=str(mock_proc_dir))
    data = collector.collect()

    assert "timestamp" in data
    assert "cpu_percent" in data
    assert isinstance(data["cpu_per_core"], list)
    assert "load_1m" in data
    assert "mem_total" in data
    assert "mem_used" in data
    assert "mem_percent" in data
    assert "disk_read_bytes_sec" in data
    assert "net_recv_bytes_sec" in data
    assert "ctx_switches_sec" in data
    assert "proc_pulse_cpu" in data
    assert "proc_pulse_mem_rss" in data


def test_process_collector_collection(mock_proc_dir: Path):
    """Test ProcessCollector returns sorted active processes."""
    collector = ProcessCollector(proc_path=str(mock_proc_dir), top_n=5)
    procs = collector.collect()

    assert isinstance(procs, list)
    if procs:
        p = procs[0]
        assert "pid" in p
        assert "name" in p
        assert "cpu_percent" in p
        assert "memory_percent" in p
        assert "num_threads" in p
