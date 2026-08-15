"""Run one bounded Gate C live phase without implicit retries."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secaware.exploratory.gate_c_live import run_gate_c_live_canary


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--live-config", type=Path, required=True)
    parser.add_argument("--app-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--mode", choices=("validate", "pilot", "remaining"), required=True)
    args = parser.parse_args()
    report = run_gate_c_live_canary(
        repo_root=args.repo_root,
        live_config_path=args.live_config,
        app_config_path=args.app_config,
        output_dir=args.output_dir,
        mode=args.mode,
        command_argv=tuple(sys.argv),
    )
    counts = report.get("counts")
    if isinstance(counts, dict):
        print(
            f"{report['status']} completed={counts['completed']} running={counts['running']} "
            f"errors={counts['errors']} pending={counts['pending']}"
        )
    else:
        print(
            f"{report['status']} validated={report['validated_assignments']} "
            f"provider_calls={report['provider_calls']} pending={report['pending']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
