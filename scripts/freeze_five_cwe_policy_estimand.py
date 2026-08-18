from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from secaware.experiments.policy_estimand import freeze_policy_estimand


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-pool-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    report = freeze_policy_estimand(
        task_pool_dir=args.task_pool_dir,
        config_path=args.config,
        run_dir=args.run_dir,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
