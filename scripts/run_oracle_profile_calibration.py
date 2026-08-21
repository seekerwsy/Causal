from __future__ import annotations

import argparse
from pathlib import Path
import sys

from secaware.oracle.profile_calibration import run_oracle_profile_calibration


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--project-root", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--policy-lock", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--semgrep-executable", required=True)
    parser.add_argument("--bandit-executable", required=True)
    parser.add_argument("--timeout-seconds", type=float, default=120.0)
    args = parser.parse_args()
    report = run_oracle_profile_calibration(
        project_root=args.project_root,
        manifest_path=args.manifest,
        policy_lock_path=args.policy_lock,
        output_dir=args.output_dir,
        semgrep_executable=args.semgrep_executable,
        bandit_executable=args.bandit_executable,
        timeout_seconds=args.timeout_seconds,
        command_argv=tuple(sys.argv),
    )
    print(report["status"])
    return 0 if report["status"] == "ORACLE_PROFILE_CALIBRATION_PASSED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
