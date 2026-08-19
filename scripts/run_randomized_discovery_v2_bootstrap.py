from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.randomized_discovery_v2_bootstrap import (
    run_randomized_discovery_v2_bootstrap,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one discovery-v2 task-block bootstrap.")
    parser.add_argument("--table-dir", type=Path, required=True)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--analysis-config", type=Path, required=True)
    parser.add_argument("--bootstrap-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--engineering-replicates", type=int)
    args = parser.parse_args()
    report = run_randomized_discovery_v2_bootstrap(
        table_dir=args.table_dir,
        reference_dir=args.reference_dir,
        analysis_config_path=args.analysis_config,
        bootstrap_config_path=args.bootstrap_config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
        engineering_replicates=args.engineering_replicates,
    )
    print(
        f"{report['status']} successful={report['successful_replicates']} "
        f"failed={report['failed_replicates']} support={report['support_numerator']}/"
        f"{report['support_denominator']} hypotheses={report['frozen_hypotheses']}"
    )
    return 0 if report["status"] != "DISCOVERY_V2_BOOTSTRAP_FAILED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
