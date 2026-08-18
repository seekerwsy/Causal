"""Authenticate two held-out Gate C archives and estimate the frozen policy ITT."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secaware.experiments.held_out_policy_analysis import analyze_held_out_policy_itt


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--qwen-archive", type=Path, required=True)
    parser.add_argument("--phi-archive", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = analyze_held_out_policy_itt(
        repo_root=args.repo_root,
        config_path=args.config,
        model_archives={
            "qwen2.5-coder-7b-instruct": args.qwen_archive,
            "phi-4-14b": args.phi_archive,
        },
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    counts = report["counts"]
    print(
        f"{report['status']} assignments={counts['assignments']} "
        f"primary_effects={counts['primary_effects']} errors={counts['errors']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
