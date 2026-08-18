from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from secaware.functional_audit.main_task_pool import freeze_main_task_pool


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--baseline-prepared-dir", type=Path, required=True)
    parser.add_argument("--baseline-reconciled-dir", type=Path, required=True)
    parser.add_argument("--supplement-prepared-dir", type=Path, required=True)
    parser.add_argument("--supplement-reconciled-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    report = freeze_main_task_pool(
        baseline_prepared_dir=args.baseline_prepared_dir,
        baseline_reconciled_dir=args.baseline_reconciled_dir,
        supplement_prepared_dir=args.supplement_prepared_dir,
        supplement_reconciled_dir=args.supplement_reconciled_dir,
        config_path=args.config,
        run_dir=args.run_dir,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
