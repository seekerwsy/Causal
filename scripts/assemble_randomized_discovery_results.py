"""Assemble one complete five-CWE randomized-discovery model stratum."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secaware.exploratory.randomized_discovery_results import (
    assemble_randomized_discovery_results,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--analysis-config", type=Path, required=True)
    parser.add_argument("--estimand-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    summary = assemble_randomized_discovery_results(
        plan_dir=args.plan_dir,
        run_dir=args.run_dir,
        analysis_config_path=args.analysis_config,
        estimand_config_path=args.estimand_config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(
        f"{summary['status']} model={summary['model_id']} rows={summary['rows']} "
        f"tasks={summary['independent_tasks']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
