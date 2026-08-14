"""Build immutable inputs for the outcome-blind LLM facts extraction canary."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import socket
import sys
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from secaware.io.jsonl import write_jsonl
from secaware.schema.experiments import PromptRole
from secaware.schema.records import PromptRecord


def _canonical(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _write_json(path: Path, value: object) -> None:
    path.write_bytes(_canonical(value) + b"\n")


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]


def build(
    *,
    source_prompts: Path,
    selection_path: Path,
    output_dir: Path,
    command_argv: tuple[str, ...],
) -> dict[str, object]:
    if output_dir.exists():
        raise FileExistsError(output_dir)
    selection = json.loads(selection_path.read_text(encoding="utf-8"))
    if (
        selection.get("schema_version") != "1.0"
        or selection.get("selection_policy", {}).get("outcome_blind") is not True
    ):
        raise ValueError("canary selection failed validation")
    source = {
        item["prompt_id"]: PromptRecord.model_validate(item)
        for item in _read_jsonl(source_prompts)
    }
    selected: list[PromptRecord] = []
    manifest_rows: list[dict[str, object]] = []
    seen: set[str] = set()
    for item in selection.get("prompts", []):
        prompt_id = item.get("prompt_id")
        if type(prompt_id) is not str or prompt_id in seen:
            raise ValueError("duplicate or invalid canary prompt")
        prompt = source.get(prompt_id)
        if (
            prompt is None
            or prompt.split != "discover"
            or prompt.prompt_role is not PromptRole.NEUTRAL_BASELINE
            or prompt.cwe != item.get("cwe")
            or type(item.get("stratum")) is not str
            or not item["stratum"]
        ):
            raise ValueError(f"canary prompt provenance mismatch: {prompt_id}")
        seen.add(prompt_id)
        selected.append(prompt)
        manifest_rows.append(
            {
                "prompt_id": prompt.prompt_id,
                "task_id": prompt.task_id,
                "cwe": prompt.cwe,
                "stratum": item["stratum"],
                "prompt_sha256": prompt.prompt_sha256,
            }
        )
    quotas = selection["selection_policy"]["cwe_quotas"]
    counts = Counter(item.cwe for item in selected)
    if not selected or dict(sorted(counts.items())) != dict(sorted(quotas.items())):
        raise ValueError("canary CWE quota failed validation")
    selected.sort(key=lambda item: item.prompt_id)
    manifest_rows.sort(key=lambda item: str(item["prompt_id"]))

    output_dir.mkdir(parents=True, exist_ok=False)
    write_jsonl(output_dir / "prompts.jsonl", selected)
    (output_dir / "prompt-attestations.jsonl").write_bytes(b"")
    _write_json(output_dir / "selected-prompts.json", manifest_rows)
    _write_json(output_dir / "command.json", {"argv": list(command_argv)})
    _write_json(
        output_dir / "environment.json",
        {
            "captured_at_utc": datetime.now(UTC).isoformat(),
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "python": sys.version,
            "python_executable": sys.executable,
            "working_directory": os.getcwd(),
        },
    )
    report: dict[str, object] = {
        "schema_version": "1.0",
        "selection_id": selection["selection_id"],
        "status": "INPUTS_READY",
        "counts": {
            "prompts": len(selected),
            "independent_tasks": len({item.task_id for item in selected}),
            "by_cwe": dict(sorted(counts.items())),
            "failed": 0,
            "running": 0,
            "pending": 0,
        },
        "source_prompts_sha256": hashlib.sha256(source_prompts.read_bytes()).hexdigest(),
        "selection_sha256": hashlib.sha256(selection_path.read_bytes()).hexdigest(),
        "artifacts": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(output_dir.iterdir())
            if path.is_file()
        },
    }
    _write_json(output_dir / "report.json", report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-prompts", type=Path, required=True)
    parser.add_argument("--selection", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = build(
        source_prompts=args.source_prompts,
        selection_path=args.selection,
        output_dir=args.output_dir,
        command_argv=tuple(sys.argv),
    )
    print(json.dumps(report, ensure_ascii=False, sort_keys=True))


if __name__ == "__main__":
    main()
