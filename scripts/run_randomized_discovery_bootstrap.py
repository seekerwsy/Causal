"""Run the four-arm task-cluster bootstrap for one discovery model."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secaware.exploratory.randomized_discovery_bootstrap import (
    run_randomized_discovery_bootstrap,
)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--assembly-dir", type=Path, required=True)
    parser.add_argument("--reference-dir", type=Path, required=True)
    parser.add_argument("--analysis-config", type=Path, required=True)
    parser.add_argument("--gate-a-config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--engineering-replicates", type=int)
    args = parser.parse_args()
    report = run_randomized_discovery_bootstrap(
        assembly_dir=args.assembly_dir,
        reference_dir=args.reference_dir,
        analysis_config_path=args.analysis_config,
        gate_a_config_path=args.gate_a_config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
        engineering_replicates=args.engineering_replicates,
    )
    print(
        f"{report['status']} model={report['model_id']} "
        f"successful={report['successful_replicates']} "
        f"failed={report['failed_replicates']} "
        f"hypotheses={report['frozen_hypotheses']}"
    )
    return 0 if report["status"] != "RANDOMIZED_DISCOVERY_BOOTSTRAP_FAILED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
