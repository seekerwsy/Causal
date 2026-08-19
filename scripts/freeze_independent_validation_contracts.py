from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secaware.exploratory.independent_validation_contracts import (
    freeze_independent_validation_contracts,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--restricted-dir", type=Path, required=True)
    parser.add_argument("--public-dir", type=Path, required=True)
    args = parser.parse_args()
    report = freeze_independent_validation_contracts(
        repo_root=args.repo_root.resolve(),
        config_path=args.config.resolve(),
        restricted_dir=args.restricted_dir.resolve(),
        public_dir=args.public_dir.resolve(),
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
