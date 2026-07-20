#!/usr/bin/env python3
# Demo compatibility runner: re-runs verify.
import subprocess, sys
raise SystemExit(subprocess.call([sys.executable, 'verify.py']))
