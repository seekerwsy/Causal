"""Run the bounded Gate B LLM intervention and blind extraction canary."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys

from secaware.exploratory.gate_b import run_exploratory_gate_b


def _load_env_file(path: Path) -> None:
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key and key not in os.environ:
            os.environ[key] = value.strip()


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--gate-b-config", type=Path, required=True)
    parser.add_argument("--app-config", type=Path, required=True)
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    _load_env_file(args.env_file)
    report = run_exploratory_gate_b(
        repo_root=args.repo_root,
        gate_b_config_path=args.gate_b_config,
        app_config_path=args.app_config,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
