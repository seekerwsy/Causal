#!/usr/bin/env python3
"""Identify which locked analyzer fails inside SecAware process isolation."""

from __future__ import annotations

import argparse
from dataclasses import asdict
import json
from pathlib import Path
import shutil
import tempfile

from secaware.errors import SecAwareError
from secaware.oracle.runner import run_analyzer_process, validate_analyzer_runtime


def _runtime() -> dict[str, object]:
    try:
        value = validate_analyzer_runtime()
        return {"status": "PASS", "capabilities": asdict(value)}
    except SecAwareError as error:
        return {"status": "ERROR", "error_code": error.code.name}


def _analyzer(name: str) -> dict[str, object]:
    executable = shutil.which(name)
    if executable is None:
        return {"status": "ERROR", "error_code": "ANALYZER_MISSING"}
    resolved = Path(executable).resolve(strict=True)
    first_line = resolved.read_bytes().splitlines()[0][:512].decode("utf-8", errors="replace")
    try:
        with tempfile.TemporaryDirectory(prefix=f"secaware-{name}-diagnostic-") as root:
            result = run_analyzer_process(
                (executable, "--version"),
                cwd=Path(root),
                timeout_seconds=30.0,
                max_stdout_bytes=4096,
                max_stderr_bytes=4096,
            )
        return {
            "status": "PASS" if result.returncode == 0 else "ERROR",
            "returncode": result.returncode,
            "stdout": result.stdout.decode("utf-8", errors="replace"),
            "argv_sha256": result.argv_sha256,
            "resolved_executable": str(resolved),
            "first_line": first_line,
        }
    except SecAwareError as error:
        return {
            "status": "ERROR",
            "error_code": error.code.name,
            "resolved_executable": str(resolved),
            "first_line": first_line,
        }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(f"refusing to overwrite {args.output}")
    payload = {
        "schema_version": "1.0",
        "runtime": _runtime(),
        "analyzers": {name: _analyzer(name) for name in ("semgrep", "bandit")},
    }
    args.output.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(payload, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
