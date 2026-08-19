from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.independent_validation_analysis_table import (
    build_independent_validation_analysis_table,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build the frozen independent validation table.")
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = build_independent_validation_analysis_table(
        repo_root=args.repo_root,
        config_path=args.config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    counts = report["counts"]
    print(
        f"{report['status']} complete={counts['complete']} errors={counts['errors']} "
        f"pending={counts['pending']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
