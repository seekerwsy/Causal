from __future__ import annotations

import argparse
import sys
from pathlib import Path

from secaware.exploratory.randomized_discovery_v3_functional_fci import (
    run_randomized_discovery_v3_functional_fci,
)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run one functional discovery-v3 FCI view.")
    parser.add_argument("--table-dir", type=Path, required=True)
    parser.add_argument("--analysis-config", type=Path, required=True)
    parser.add_argument("--model-id", required=True)
    parser.add_argument("--view-id", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run_randomized_discovery_v3_functional_fci(
        table_dir=args.table_dir,
        analysis_config_path=args.analysis_config,
        model_id=args.model_id,
        view_id=args.view_id,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(
        f"{report['status']} model={report['model_id']} view={report['view_id']} "
        f"edges={report['raw_pag_edges']} possible_czy={report['raw_possible_czy']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
