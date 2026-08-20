"""Summarize a complete two-arm D_DEV canary without confirmatory inference."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.dev_canary_analysis import analyze_dev_canary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--live-run-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = analyze_dev_canary(
        plan_dir=args.plan_dir,
        live_run_dir=args.live_run_dir,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    counts = report["counts"]
    print(
        f"{report['status']} tasks={counts['tasks']} assignments={counts['assignments']} "
        f"unknown_security={counts['security_unknown']} "
        f"unknown_functional={counts['functional_unknown']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
