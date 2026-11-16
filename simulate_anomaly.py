#!/usr/bin/env python3
"""ProcPulse AI — Safe Synthetic Telemetry Anomaly Simulator.

Demonstration script for live project review (college ITR).
Safely triggers controlled CPU spikes, memory surges, disk I/O bursts,
and file descriptor leaks to showcase ML and statistical anomaly detection in real time.
Guarantees 100% clean resource cleanup under all circumstances.
"""

import os
import sys
import time
import math
import signal
import tempfile
import argparse
import threading
from typing import List, Any

# ANSI Colors for terminal output
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
BOLD = "\033[1m"
RESET = "\033[0m"

stop_requested = threading.Event()


def handle_signal(sig: int, frame: Any) -> None:
    """Safely catch interrupts and request immediate termination."""
    print(f"\n{YELLOW}[!] Received interrupt signal ({sig}). Cleaning up resources...{RESET}")
    stop_requested.set()


signal.signal(signal.SIGINT, handle_signal)
signal.signal(signal.SIGTERM, handle_signal)


def cpu_burn_worker(worker_id: int, duration_sec: float) -> None:
    """Tight mathematical computation loop to safely max out a CPU core."""
    end_time = time.time() + duration_sec
    while time.time() < end_time and not stop_requested.is_set():
        # Intense floating-point operations
        _ = math.sqrt(1234567.89) * math.sin(987654.32) * math.cos(34567.12)


def simulate_cpu(duration: float = 12.0, num_workers: int = 4) -> None:
    """Trigger a controlled CPU utilization spike across threads."""
    print(f"{CYAN}[CPU SPIKE]{RESET} Spawning {num_workers} computational burn threads for {duration}s...")
    threads: List[threading.Thread] = []
    try:
        for i in range(num_workers):
            t = threading.Thread(target=cpu_burn_worker, args=(i, duration), daemon=True)
            threads.append(t)
            t.start()

        start = time.time()
        while time.time() - start < duration and not stop_requested.is_set():
            time.sleep(0.5)
            elapsed = time.time() - start
            print(f"\r  └─ Burning CPU: {elapsed:.1f}s / {duration}s [Check Dashboard CPU Chart]", end="", flush=True)
        print()
    finally:
        stop_requested.set()
        for t in threads:
            t.join(timeout=1.0)
        stop_requested.clear()
        print(f"{GREEN}[✓] CPU spike terminated cleanly. Cores returned to idle.{RESET}\n")


def simulate_memory(target_mb: int = 600, duration: float = 10.0) -> None:
    """Safely allocate memory blocks in RAM, hold, and release."""
    print(f"{CYAN}[MEMORY SPIKE]{RESET} Allocating {target_mb} MB in RAM for {duration}s...")
    chunks: List[bytearray] = []
    try:
        # Allocate in 50MB increments
        chunk_size = 50 * 1024 * 1024
        chunks_count = target_mb // 50
        for i in range(chunks_count):
            if stop_requested.is_set():
                break
            # Allocate and dirty each page so OS actually assigns physical RAM (RSS)
            b = bytearray(chunk_size)
            for page in range(0, chunk_size, 4096):
                b[page] = 1
            chunks.append(b)
            print(f"\r  └─ Allocated {(i + 1) * 50} MB / {target_mb} MB", end="", flush=True)
            time.sleep(0.15)
        print()

        start = time.time()
        while time.time() - start < duration and not stop_requested.is_set():
            time.sleep(0.5)
            elapsed = time.time() - start
            print(f"\r  └─ Holding {target_mb} MB in memory: {elapsed:.1f}s / {duration}s [Check Memory Chart]", end="", flush=True)
        print()
    finally:
        print(f"{YELLOW}[*] Freeing allocated memory chunks...{RESET}")
        chunks.clear()
        import gc
        gc.collect()
        print(f"{GREEN}[✓] Memory completely deallocated and garbage-collected.{RESET}\n")


def simulate_io(file_size_mb: int = 150, duration: float = 10.0) -> None:
    """Safely create rapid disk write and read bursts in temporary storage."""
    print(f"{CYAN}[DISK I/O BURST]{RESET} Generating heavy disk read/write throughput for {duration}s...")
    temp_dir = tempfile.mkdtemp(prefix="procpulse_demo_")
    test_file = os.path.join(temp_dir, "io_burst.tmp")
    data_block = b"X" * (1024 * 1024)  # 1MB block

    try:
        end_time = time.time() + duration
        iteration = 0
        while time.time() < end_time and not stop_requested.is_set():
            iteration += 1
            # Sequential burst write
            with open(test_file, "wb") as f:
                for _ in range(file_size_mb):
                    if stop_requested.is_set():
                        break
                    f.write(data_block)
                f.flush()
                try:
                    os.fsync(f.fileno())
                except Exception:
                    pass

            # Sequential read
            with open(test_file, "rb") as f:
                while True:
                    chunk = f.read(1024 * 1024)
                    if not chunk or stop_requested.is_set():
                        break

            elapsed = duration - max(0.0, end_time - time.time())
            print(f"\r  └─ Disk I/O Pass #{iteration}: {elapsed:.1f}s / {duration}s [Check Disk I/O Chart]", end="", flush=True)
        print()
    finally:
        # Guarantee removal of temporary files
        try:
            if os.path.exists(test_file):
                os.remove(test_file)
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)
        except Exception as e:
            print(f"Cleanup warning: {e}")
        print(f"{GREEN}[✓] Temporary I/O burst files flushed and unlinked.{RESET}\n")


def simulate_fd_leak(count: int = 60, duration: float = 10.0) -> None:
    """Safely simulate a sudden file descriptor leak to trigger suspicious process detector."""
    print(f"{CYAN}[SUSPICIOUS FD LEAK]{RESET} Opening {count} file descriptors rapidly for {duration}s...")
    open_handles = []
    temp_dir = tempfile.mkdtemp(prefix="procpulse_fd_")

    try:
        for i in range(count):
            if stop_requested.is_set():
                break
            filepath = os.path.join(temp_dir, f"leak_{i}.tmp")
            handle = open(filepath, "w+")
            open_handles.append((handle, filepath))
            time.sleep(0.03)

        print(f"  └─ Successfully opened {len(open_handles)} active file descriptors.")
        start = time.time()
        while time.time() - start < duration and not stop_requested.is_set():
            time.sleep(0.5)
            elapsed = time.time() - start
            print(f"\r  └─ Holding open descriptors: {elapsed:.1f}s / {duration}s [Check Suspicious Process Card]", end="", flush=True)
        print()
    finally:
        print(f"{YELLOW}[*] Closing all opened file descriptors...{RESET}")
        for handle, path in open_handles:
            try:
                handle.close()
                if os.path.exists(path):
                    os.remove(path)
            except Exception:
                pass
        try:
            if os.path.exists(temp_dir):
                os.rmdir(temp_dir)
        except Exception:
            pass
        print(f"{GREEN}[✓] All leaked file descriptors safely closed and cleaned up.{RESET}\n")


def run_all(duration: float = 10.0) -> None:
    """Orchestrate an end-to-end multi-anomaly demonstration sequence."""
    print(f"{BOLD}{CYAN}=== Starting ProcPulse AI Full Anomaly Simulation Sequence ==={RESET}")
    print(f"Ensure the web dashboard is open at http://localhost:8000\n")

    time.sleep(1.0)
    simulate_cpu(duration=duration, num_workers=4)

    if stop_requested.is_set():
        return

    print("Resting 3 seconds before next anomaly...")
    time.sleep(3.0)
    simulate_memory(target_mb=500, duration=duration)

    if stop_requested.is_set():
        return

    print("Resting 3 seconds before next anomaly...")
    time.sleep(3.0)
    simulate_io(file_size_mb=100, duration=duration)

    if stop_requested.is_set():
        return

    print("Resting 3 seconds before next anomaly...")
    time.sleep(3.0)
    simulate_fd_leak(count=50, duration=duration)

    print(f"{BOLD}{GREEN}=== Demonstration Sequence Complete! ==={RESET}")


def main() -> None:
    """Parse CLI options and dispatch simulated anomaly."""
    parser = argparse.ArgumentParser(
        description="ProcPulse AI — Real-Time Linux Telemetry Anomaly Simulator"
    )
    parser.add_argument("--cpu", action="store_true", help="Trigger safe CPU spike")
    parser.add_argument("--memory", action="store_true", help="Trigger safe RAM allocation spike")
    parser.add_argument("--io", action="store_true", help="Trigger safe disk I/O burst")
    parser.add_argument("--fd", action="store_true", help="Trigger safe File Descriptor leak")
    parser.add_argument("--all", action="store_true", help="Run full sequential demonstration")
    parser.add_argument("--duration", type=float, default=10.0, help="Duration in seconds (default: 10s)")
    parser.add_argument("--memory-mb", type=int, default=500, help="RAM target in MB for --memory (default: 500)")
    parser.add_argument("--count", type=int, default=60, help="FD count target for --fd (default: 60)")

    args = parser.parse_args()

    if not any([args.cpu, args.memory, args.io, args.fd, args.all]):
        # Default to interactive or full demo if no flags provided
        print(f"{BOLD}ProcPulse AI Synthetic Anomaly Injector{RESET}")
        print("Usage:")
        print("  python simulate_anomaly.py --cpu        # CPU surge")
        print("  python simulate_anomaly.py --memory     # Memory allocation spike")
        print("  python simulate_anomaly.py --io         # Disk I/O throughput burst")
        print("  python simulate_anomaly.py --fd         # Sudden File Descriptor leak")
        print("  python simulate_anomaly.py --all        # Complete demonstration sequence")
        sys.exit(0)

    try:
        if args.all:
            run_all(duration=args.duration)
        elif args.cpu:
            simulate_cpu(duration=args.duration)
        elif args.memory:
            simulate_memory(target_mb=args.memory_mb, duration=args.duration)
        elif args.io:
            simulate_io(duration=args.duration)
        elif args.fd:
            simulate_fd_leak(count=args.count, duration=args.duration)
    except KeyboardInterrupt:
        print("\nSimulation aborted by user.")


if __name__ == "__main__":
    main()
