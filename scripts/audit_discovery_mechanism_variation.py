from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secaware.exploratory.discovery_mechanism_audit import audit_discovery_mechanism_variation


def main() -> int:
    parser = argparse.ArgumentParser(description="Audit discovery code-mechanism variation.")
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = audit_discovery_mechanism_variation(
        repo_root=args.repo_root,
        config_path=args.config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    counts = report["counts"]
    print(
        f"{report['status']} rows={counts['rows']} "
        f"tasks_per_model={counts['tasks_per_model']} errors={counts['errors']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
