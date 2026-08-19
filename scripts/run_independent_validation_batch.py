from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.independent_validation_batch import (
    run_independent_validation_batch,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--completed-run-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run_independent_validation_batch(
        repo_root=args.repo_root,
        config_path=args.config,
        completed_run_dir=args.completed_run_dir,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(report)


if __name__ == "__main__":
    main()
