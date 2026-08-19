from __future__ import annotations

import argparse
from pathlib import Path

from secaware.exploratory.independent_validation_freeze import (
    freeze_independent_validation_runtime,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--app-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = freeze_independent_validation_runtime(
        repo_root=args.repo_root,
        config_path=args.config,
        app_config_path=args.app_config,
        output_dir=args.output_dir,
        command_argv=tuple(__import__("sys").argv),
    )
    print(report)


if __name__ == "__main__":
    main()
