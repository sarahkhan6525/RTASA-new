"""
CLI entry point for the Section V-D steganalysis evaluation (Fig. 3
reproduction). See `rtasa/steganalysis/evaluate.py` for the methodology.

Usage:

    python -m scripts.run_steganalysis                 # full, paper-scale sweep
    python -m scripts.run_steganalysis --quick          # fast sanity check
"""

from __future__ import annotations

from rtasa.steganalysis.evaluate import main

if __name__ == "__main__":
    main()
