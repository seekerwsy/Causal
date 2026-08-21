from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.independent_validation_analysis_bootstrap import (
    run_independent_validation_analysis_bootstrap,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bootstrap the frozen independent validation edge."
    )
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--table-dir", type=Path, required=True)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--analysis-config", type=Path, required=True)
    parser.add_argument("--bootstrap-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--engineering-replicates", type=int)
    args = parser.parse_args()
    report = run_independent_validation_analysis_bootstrap(
        repo_root=args.repo_root,
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
        f"{report['support_denominator']} decision={report['replication_decision']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
