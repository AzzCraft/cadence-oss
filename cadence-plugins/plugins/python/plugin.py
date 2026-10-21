#!/usr/bin/env python3
"""Source-checkout entry point; implementation is included in the wheel."""
from cadence_plugin_python.plugin import cli

if __name__ == "__main__":
    raise SystemExit(cli())
