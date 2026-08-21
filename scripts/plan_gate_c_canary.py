"""Create the exact zero-provider Gate C code-generation plan."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from secaware.exploratory.gate_c import plan_gate_c_canary


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--gate-c-config", type=Path, required=True)
    parser.add_argument("--app-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = plan_gate_c_canary(
        repo_root=args.repo_root,
        gate_c_config_path=args.gate_c_config,
        app_config_path=args.app_config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
