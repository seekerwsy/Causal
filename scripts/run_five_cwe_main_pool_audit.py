"""Prepare or execute the outcome-blind five-CWE main-pool audit."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from secaware.functional_audit.main_pool import (
    prepare_main_pool_audit,
    run_main_pool_audit,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(dest="action", required=True)

    prepare = subparsers.add_parser("prepare")
    prepare.add_argument("--source-record-audit", type=Path, required=True)
    prepare.add_argument("--split-simulations", type=Path, required=True)
    prepare.add_argument("--config", type=Path, required=True)
    prepare.add_argument("--run-dir", type=Path, required=True)

    live = subparsers.add_parser("run")
    live.add_argument("--prepared-dir", type=Path, required=True)
    live.add_argument("--config", type=Path, required=True)
    live.add_argument("--run-dir", type=Path, required=True)

    args = parser.parse_args()
    if args.action == "prepare":
        report = prepare_main_pool_audit(
            source_record_audit=args.source_record_audit,
            split_simulations=args.split_simulations,
            config_path=args.config,
            run_dir=args.run_dir,
            command_argv=tuple(sys.argv),
        )
    else:
        report = run_main_pool_audit(
            prepared_dir=args.prepared_dir,
            live_config_path=args.config,
            run_dir=args.run_dir,
            command_argv=tuple(sys.argv),
        )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
