#!/usr/bin/env python3
"""Copy the one component VERSION author into the CLI's embedded build input."""
import argparse
from pathlib import Path
import re

ROOT=Path(__file__).resolve().parents[1]
OUTPUT=ROOT/'cadence-core/cmd/cadence/release_version.txt'


def valid_version(version):
    core = r'(?:0|[1-9][0-9]*)'
    match = re.fullmatch(core+r'\.'+core+r'\.'+core+r'(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?', version)
    return bool(match) and all(not part.isdigit() or part == '0' or not part.startswith('0') for part in (match.group(1) or '').split('.'))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    args=parser.parse_args()
    version=(ROOT/'VERSION').read_text().strip()
    if not valid_version(version):
        raise SystemExit('invalid Cadence release VERSION')
    expected=version+'\n'
    if args.check:
        if not OUTPUT.is_file() or OUTPUT.read_text()!=expected:raise SystemExit('embedded CLI version is stale; run tools/generate_build_identity.py')
    else:OUTPUT.write_text(expected)


if __name__=='__main__':main()
