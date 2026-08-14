#!/usr/bin/env python3
"""Capture one raw Ollama OpenAI-compatible response without credentials."""

from __future__ import annotations

import argparse
import datetime as dt
import json
from pathlib import Path
from typing import Any

from openai import OpenAI


def _read_first_request(path: Path) -> dict[str, Any]:
    with path.open("r", encoding="utf-8") as stream:
        for line in stream:
            if line.strip():
                value = json.loads(line)
                if not isinstance(value, dict):
                    raise ValueError("the first request is not a JSON object")
                return value
    raise ValueError("the request file is empty")


def _write_json(path: Path, value: object) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--request-path", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--base-url", default="http://127.0.0.1:11434/v1")
    parser.add_argument("--system-template", required=True)
    parser.add_argument(
        "--reasoning-effort",
        choices=("none", "low", "medium", "high"),
        default=None,
    )
    args = parser.parse_args()

    if args.output_dir.exists():
        raise FileExistsError(f"refusing to overwrite {args.output_dir}")
    args.output_dir.mkdir(parents=True)

    request = _read_first_request(args.request_path)
    parameter_values = request.get("parameters", {}).get("values", {})
    if not isinstance(parameter_values, dict):
        raise ValueError("request parameters are invalid")

    payload: dict[str, Any] = {
        "model": request["model_id"],
        "messages": [
            {"role": "system", "content": args.system_template},
            {"role": "user", "content": request["prompt"]},
        ],
        **parameter_values,
        "seed": request["seed_id"],
    }
    if args.reasoning_effort is not None:
        payload["reasoning_effort"] = args.reasoning_effort

    started_at = dt.datetime.now(dt.timezone.utc)
    client = OpenAI(base_url=args.base_url, api_key="ollama-local", timeout=180.0)
    try:
        response = client.chat.completions.create(**payload)
    except Exception as error:
        _write_json(
            args.output_dir / "error.json",
            {
                "schema_version": "1.0",
                "error_type": type(error).__name__,
                "error_message": str(error),
            },
        )
        raise
    finally:
        finished_at = dt.datetime.now(dt.timezone.utc)

    _write_json(
        args.output_dir / "request.json",
        {
            "schema_version": "1.0",
            "request_id": request.get("request_id"),
            "base_url": args.base_url,
            "payload": payload,
            "credential_recorded": False,
        },
    )
    _write_json(args.output_dir / "response.json", response.model_dump(mode="json"))
    _write_json(
        args.output_dir / "timing.json",
        {
            "schema_version": "1.0",
            "started_at_utc": started_at.isoformat(),
            "finished_at_utc": finished_at.isoformat(),
            "elapsed_seconds": (finished_at - started_at).total_seconds(),
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
