"""Run raw and JCI-constrained reference FCI for one discovery stratum."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secaware.exploratory.randomized_discovery_fci import (
    run_randomized_discovery_reference_fci,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assembly-dir", type=Path, required=True)
    parser.add_argument("--analysis-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run_randomized_discovery_reference_fci(
        assembly_dir=args.assembly_dir,
        analysis_config_path=args.analysis_config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(
        f"{report['status']} model={report['model_id']} rows={report['rows']} "
        f"raw_edges={report['raw_pag_edges']} jci_edges={report['jci_constrained_pag_edges']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
