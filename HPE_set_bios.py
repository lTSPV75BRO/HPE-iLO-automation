#!/usr/bin/env python3
"""
Launcher for hpe_set_bios (run from repo without installing).
When the package is installed via pip, use the 'hpe-set-bios' command instead.
"""
import os
import sys

# Run from repo: add repo root so 'hpe_set_bios' package is found
_script_dir = os.path.dirname(os.path.abspath(__file__))
if _script_dir not in sys.path:
    sys.path.insert(0, _script_dir)

from hpe_set_bios.cli import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user (Ctrl+C).", file=sys.stderr)
        sys.exit(130)
