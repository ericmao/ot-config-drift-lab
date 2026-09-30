#!/usr/bin/env python3
"""Run the research prototype without installing a package."""

from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from otdrift.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
