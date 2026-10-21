#!/usr/bin/env python3
"""Run the delivered contract gate independently of the caller's directory."""
import subprocess
import sys
from pathlib import Path
raise SystemExit(subprocess.call([sys.executable, str(Path(__file__).with_name("verify.py"))]))
