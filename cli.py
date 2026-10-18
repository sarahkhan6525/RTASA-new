#!/usr/bin/env python3
"""
Top-level convenience entry point.

    python cli.py demo          # run scripts/demo.py end to end
    python cli.py covers        # (re)generate the synthetic carrier images
    python cli.py serve         # run the FastAPI backend with uvicorn
    python cli.py test          # run the full pytest suite
"""

from __future__ import annotations

import argparse
import subprocess
import sys


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=["demo", "covers", "serve", "test"])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", default="8000")
    args = parser.parse_args()

    if args.command == "demo":
        from scripts.demo import real_pipeline_demo, toy_example

        toy_example()
        real_pipeline_demo()
        return 0

    if args.command == "covers":
        from carriers.generate_carriers import save_covers
        from pathlib import Path

        written = save_covers(Path(__file__).parent / "carriers" / "generated")
        print(f"Wrote {len(written)} covers.")
        return 0

    if args.command == "serve":
        return subprocess.call(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--reload", "--host", args.host, "--port", args.port]
        )

    if args.command == "test":
        return subprocess.call([sys.executable, "-m", "pytest", "tests/", "-v"])

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
