from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.independent_validation_analysis_fci import (
    run_independent_validation_analysis_fci,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run frozen independent validation FCI/JCI.")
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--table-dir", type=Path, required=True)
    parser.add_argument("--analysis-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run_independent_validation_analysis_fci(
        repo_root=args.repo_root,
        table_dir=args.table_dir,
        analysis_config_path=args.analysis_config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(
        f"{report['status']} raw_match={report['raw_pag_frozen_edge_match']} "
        f"jci_match={report['jci_constrained_pag_frozen_edge_match']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
