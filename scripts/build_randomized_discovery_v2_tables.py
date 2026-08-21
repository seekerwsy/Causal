from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secaware.exploratory.randomized_discovery_v2_table import (
    build_randomized_discovery_v2_tables,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Build discovery-v2 mechanism tables.")
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = build_randomized_discovery_v2_tables(
        repo_root=args.repo_root,
        config_path=args.config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    counts = report["counts"]
    print(
        f"{report['status']} joined_rows={counts['joined_rows']} "
        f"views={counts['views']} errors={counts['errors']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
