#!/usr/bin/env python3
"""Capture the Linux Oracle runtime probe's otherwise suppressed diagnostics."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

from secaware.oracle.runner import _LINUX_RUNTIME_PROBE_SOURCE


def _run(*, executable: str | None) -> dict[str, object]:
    environment = {
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": "",
        "PYTHONHASHSEED": "0",
        "PYTHONIOENCODING": "utf-8",
        "PYTHONUTF8": "1",
    }
    completed = subprocess.run(
        (os.path.abspath(sys.executable), "-I", "-S", "-c", _LINUX_RUNTIME_PROBE_SOURCE),
        executable=executable,
        env=environment,
        shell=False,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10.0,
        check=False,
    )
    return {
        "executable": executable,
        "returncode": completed.returncode,
        "stdout": completed.stdout.decode("utf-8", errors="replace"),
        "stderr": completed.stderr.decode("utf-8", errors="replace"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite {args.output}")
    payload = {
        "schema_version": "1.0",
        "python_executable": sys.executable,
        "runs": [
            _run(executable=None),
            _run(executable="/proc/self/exe"),
        ],
    }
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
