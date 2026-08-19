from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secaware.exploratory.external_validation_semantic_pool import (
    freeze_external_validation_semantic_pool,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    report = freeze_external_validation_semantic_pool(
        repo_root=args.repo_root.resolve(),
        config_path=args.config.resolve(),
        run_dir=args.run_dir.resolve(),
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
