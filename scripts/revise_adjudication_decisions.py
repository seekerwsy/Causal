from __future__ import annotations

import argparse
from datetime import UTC, datetime
import hashlib
import json
from pathlib import Path
import shutil
import sys

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter

from secaware.dataset_adjudication.schema import CodexDecision


class DecisionCorrection(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1.0"
    packet_id: str = Field(pattern=r"^(neutrality|cluster-rel)-[0-9a-f]{20}$")
    pass_id: str = Field(pattern=r"^[AB]$")
    evidence_quotes: tuple[str, ...] = Field(min_length=1)
    correction_reason: str = Field(min_length=1)


DECISION_ADAPTER = TypeAdapter(CodexDecision)


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_jsonl(path: Path, adapter) -> list:
    values = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            raise ValueError(f"blank JSONL line at {line_number}")
        values.append(adapter.validate_json(line))
    return values


def _write_json(path: Path, value) -> None:
    path.write_text(
        json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def _write_jsonl(path: Path, values) -> None:
    path.write_text(
        "".join(
            json.dumps(
                value.model_dump(mode="json") if isinstance(value, BaseModel) else value,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for value in values
        ),
        encoding="utf-8",
        newline="\n",
    )


def revise_decision_files(
    source_dir: Path,
    corrections_path: Path,
    output_dir: Path,
    *,
    argv: tuple[str, ...],
) -> None:
    source_dir = source_dir.resolve()
    corrections_path = corrections_path.resolve()
    output_dir = output_dir.resolve()
    staging = output_dir.parent / f".{output_dir.name}.staging"
    if output_dir.exists() or staging.exists():
        raise ValueError("revision output already exists")
    pass_paths = {
        "A": source_dir / "pass-a-decisions.jsonl",
        "B": source_dir / "pass-b-decisions.jsonl",
    }
    decisions = {
        pass_id: _read_jsonl(path, DECISION_ADAPTER)
        for pass_id, path in pass_paths.items()
    }
    corrections = _read_jsonl(corrections_path, TypeAdapter(DecisionCorrection))
    correction_by_key = {}
    for correction in corrections:
        key = (correction.packet_id, correction.pass_id)
        if key in correction_by_key:
            raise ValueError("duplicate decision correction")
        correction_by_key[key] = correction
    available = {
        (decision.packet_id, decision.pass_id)
        for values in decisions.values()
        for decision in values
    }
    if set(correction_by_key) - available:
        raise ValueError("decision correction references an unknown decision")
    revised = {}
    for pass_id, values in decisions.items():
        revised_values = []
        for decision in values:
            correction = correction_by_key.get((decision.packet_id, pass_id))
            if correction is None:
                revised_values.append(decision)
                continue
            payload = decision.model_dump(mode="json")
            payload["evidence_quotes"] = list(correction.evidence_quotes)
            revised_values.append(DECISION_ADAPTER.validate_python(payload))
        revised[pass_id] = revised_values

    output_dir.parent.mkdir(parents=True, exist_ok=True)
    staging.mkdir()
    try:
        _write_jsonl(staging / "pass-a-decisions.jsonl", revised["A"])
        _write_jsonl(staging / "pass-b-decisions.jsonl", revised["B"])
        _write_jsonl(staging / "corrections.jsonl", corrections)
        _write_jsonl(staging / "commands.jsonl", ({"argv": list(argv)},))
        _write_jsonl(staging / "failures.jsonl", ())
        _write_json(
            staging / "source-decisions-manifest.json",
            {
                "schema_version": "1.0",
                "source_directory": str(source_dir),
                "source_pass_a_sha256": _sha256(pass_paths["A"]),
                "source_pass_b_sha256": _sha256(pass_paths["B"]),
                "corrections_sha256": _sha256(corrections_path),
                "correction_count": len(corrections),
                "created_at": datetime.now(UTC).isoformat(),
            },
        )
        _write_json(
            staging / "report.json",
            {
                "schema_version": "1.0",
                "status": "REVISED_DECISIONS_READY",
                "pass_a_count": len(revised["A"]),
                "pass_b_count": len(revised["B"]),
                "correction_count": len(corrections),
            },
        )
        staging.rename(output_dir)
    except BaseException:
        if staging.exists():
            shutil.rmtree(staging)
        raise


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, required=True)
    parser.add_argument("--corrections", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    arguments = parser.parse_args()
    revise_decision_files(
        arguments.source_dir,
        arguments.corrections,
        arguments.output_dir,
        argv=tuple(sys.argv),
    )


if __name__ == "__main__":
    main()
