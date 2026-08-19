from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.independent_validation_run import (
    run_independent_validation_pilot,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run_independent_validation_pilot(
        repo_root=args.repo_root,
        config_path=args.config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(report)


if __name__ == "__main__":
    main()
