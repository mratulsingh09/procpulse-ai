"""Root main.py — ProcPulse AI Application Launcher."""

import sys
import os

# Ensure procpulse package is discoverable
sys.path.insert(0, os.path.dirname(__file__))

from procpulse.main import run

if __name__ == "__main__":
    run()
