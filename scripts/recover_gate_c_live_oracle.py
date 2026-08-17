"""Copy a failed Gate C pilot and rerun only its Oracle stage."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secaware.exploratory.gate_c_live import recover_gate_c_live_oracle


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--live-config", type=Path, required=True)
    parser.add_argument("--app-config", type=Path, required=True)
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = recover_gate_c_live_oracle(
        repo_root=args.repo_root,
        live_config_path=args.live_config,
        app_config_path=args.app_config,
        source_dir=args.source_dir,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    counts = report["counts"]
    print(
        f"{report['status']} completed={counts['completed']} errors={counts['errors']} "
        f"pending={counts['pending']} new_provider_calls={report['new_provider_calls']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
