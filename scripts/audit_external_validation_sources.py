from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from secaware.exploratory.external_validation_source_audit import (
    audit_external_validation_sources,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, default=Path.cwd())
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    parser.add_argument("--codeguard-root", type=Path, required=True)
    parser.add_argument("--codeguard-archive", type=Path, required=True)
    parser.add_argument("--llmseceval-root", type=Path, required=True)
    parser.add_argument("--llmseceval-archive", type=Path, required=True)
    parser.add_argument("--seccode-root", type=Path, required=True)
    args = parser.parse_args(argv)
    report = audit_external_validation_sources(
        repo_root=args.repo_root.resolve(),
        config_path=args.config.resolve(),
        run_dir=args.run_dir.resolve(),
        codeguard_root=args.codeguard_root.resolve(),
        codeguard_archive=args.codeguard_archive.resolve(),
        llmseceval_root=args.llmseceval_root.resolve(),
        llmseceval_archive=args.llmseceval_archive.resolve(),
        seccode_root=args.seccode_root.resolve(),
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
