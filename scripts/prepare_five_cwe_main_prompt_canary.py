from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from secaware.exploratory.main_prompt_canary import prepare_main_prompt_canary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--task-pool-dir", type=Path, required=True)
    parser.add_argument("--estimand-dir", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    report = prepare_main_prompt_canary(
        task_pool_dir=args.task_pool_dir,
        estimand_dir=args.estimand_dir,
        config_path=args.config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
