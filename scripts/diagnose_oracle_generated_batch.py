#!/usr/bin/env python3
"""Run and validate each Oracle analyzer over one generated-code batch."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import shutil

from secaware.errors import SecAwareError
from secaware.io.jsonl import read_jsonl
from secaware.oracle.aggregator import (
    _materialize_batch,
    _remove_batch_tree,
    _snapshot_codes,
)
from secaware.oracle.bandit_adapter import bandit_argv, parse_bandit_report
from secaware.oracle.policy import load_policy_bundle
from secaware.oracle.runner import run_analyzer_process
from secaware.oracle.semgrep_adapter import semgrep_argv, parse_semgrep_report
from secaware.schema.records import CanonicalGeneratedCodeRecord


def _error(error: SecAwareError) -> dict[str, object]:
    return {"status": "ERROR", "error_code": error.code.name}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--code", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    if args.output_dir.exists():
        raise FileExistsError(f"refusing to overwrite {args.output_dir}")
    args.output_dir.mkdir(parents=True)

    codes = read_jsonl(args.code, CanonicalGeneratedCodeRecord)
    snapshots = _snapshot_codes(codes)
    policy = load_policy_bundle(args.policy)
    summary: dict[str, object] = {
        "schema_version": "1.0",
        "code": [
            {
                "prompt_id": item.record.prompt_id,
                "opaque_file": item.opaque_file,
                "parse_ok": item.parse_ok,
                "functional_ok": item.functional_ok,
                "starts_with_fence": item.record.code.startswith("```"),
            }
            for item in snapshots
        ],
        "analyzers": {},
    }

    analyzers = summary["analyzers"]
    assert isinstance(analyzers, dict)
    for name in ("semgrep", "bandit"):
        executable = shutil.which(name)
        if executable is None:
            analyzers[name] = {"status": "ERROR", "error_code": "ANALYZER_MISSING"}
            continue
        batch = _materialize_batch(snapshots, policy, name)
        try:
            argv = (
                semgrep_argv(Path(executable), batch.policy, Path("."))
                if name == "semgrep"
                else bandit_argv(Path(executable), batch.policy, Path("."))
            )
            try:
                result = run_analyzer_process(
                    argv,
                    cwd=batch.root,
                    timeout_seconds=120.0,
                    max_stdout_bytes=64 * 1024 * 1024,
                    max_stderr_bytes=4 * 1024 * 1024,
                )
            except SecAwareError as error:
                analyzers[name] = _error(error)
                continue
            raw_path = args.output_dir / f"{name}.raw.json"
            raw_path.write_bytes(result.stdout)
            try:
                if name == "semgrep":
                    report = parse_semgrep_report(
                        result.stdout,
                        returncode=result.returncode,
                        expected_files=batch.expected_files,
                        version=policy.semgrep_version,
                        policy_sha256=policy.combined_sha256,
                    )
                else:
                    report = parse_bandit_report(
                        result.stdout,
                        returncode=result.returncode,
                        expected_files=batch.expected_files,
                        version=policy.bandit_version,
                        policy_sha256=policy.combined_sha256,
                        constraints=policy.bandit_constraints,
                    )
                analyzers[name] = {
                    "status": "PASS",
                    "returncode": result.returncode,
                    "covered_files": list(report.covered_files),
                    "finding_count": len(report.findings),
                }
            except SecAwareError as error:
                analyzers[name] = {
                    **_error(error),
                    "returncode": result.returncode,
                    "raw_output": raw_path.name,
                }
        finally:
            _remove_batch_tree(batch.root)

    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
