from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secaware.exploratory.codesec_eval_plus_audit import audit_codesec_eval_plus_source


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--source-file", type=Path, required=True)
    parser.add_argument("--public-run-dir", type=Path, required=True)
    parser.add_argument("--restricted-run-dir", type=Path, required=True)
    args = parser.parse_args(argv)
    report = audit_codesec_eval_plus_source(
        repo_root=args.repo_root.resolve(),
        config_path=args.config.resolve(),
        source_path=args.source_file.resolve(),
        public_run_dir=args.public_run_dir.resolve(),
        restricted_run_dir=args.restricted_run_dir.resolve(),
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
