from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.independent_validation_recovery import (
    recover_invalid_functional_judge_unit,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--source-run-dir", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = recover_invalid_functional_judge_unit(
        repo_root=args.repo_root,
        config_path=args.config,
        source_run_dir=args.source_run_dir,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(report)


if __name__ == "__main__":
    main()
