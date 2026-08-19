from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.independent_validation_plan import (
    plan_independent_validation_execution,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--app-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = plan_independent_validation_execution(
        repo_root=args.repo_root,
        config_path=args.config,
        app_config_path=args.app_config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(report)


if __name__ == "__main__":
    main()
