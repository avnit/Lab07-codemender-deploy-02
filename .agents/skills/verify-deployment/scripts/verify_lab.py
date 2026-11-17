#!/usr/bin/env python3
"""
CLI & module entrypoint alias for `verify_environment.py`
([7] Using AI for Sec Ops - Creating your Sec Agent Lab / `lab_7`).
"""

from pathlib import Path
import sys

_SCRIPTS_DIR = str(Path(__file__).resolve().parent)
if _SCRIPTS_DIR not in sys.path:
    sys.path.insert(0, _SCRIPTS_DIR)

from verify_environment import *  # noqa: F401,F403
from verify_environment import main


if __name__ == "__main__":
    sys.exit(main())
