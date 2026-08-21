from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.independent_validation_effects import (
    analyze_independent_validation_effects,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze independent validation ITT diagnostics.")
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = analyze_independent_validation_effects(
        repo_root=args.repo_root,
        config_path=args.config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    counts = report["counts"]
    print(
        f"{report['status']} effects={counts['effects']} draws={counts['bootstrap_draws']} "
        f"errors={counts['errors']} pending={counts['pending']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
